/**
 * ================================================================
 * ADSOVIO BACKEND ENGINE (Production Ready)
 * ================================================================
 * Features:
 * 1. 40% VPN Tolerance (Smart Leak)
 * 2. Tier-Based Mediation (eCPM Logic)
 * 3. Telegram & Device Fingerprinting
 * 4. MongoDB Analytics
 * ================================================================
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const requestIp = require('request-ip');
const maxmind = require('maxmind');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ================= 1. CONFIGURATION & LISTS =================

// Paths to MaxMind Databases
const DB_PATH_CITY = path.join(__dirname, 'db', 'GeoLite2-City.mmdb');
const DB_PATH_ASN = path.join(__dirname, 'db', 'GeoLite2-ASN.mmdb');

// MongoDB URI (আপনার দেওয়া লিংক)
const MONGO_URI = "mongodb+srv://adsovio_backend_db_user:W7pFGH9Io6s0v7O1@cluster0.0cctlen.mongodb.net/?appName=Cluster0";

// Telegram Bot Token (TMA ভ্যালিডেশনের জন্য .env ফাইলে রাখা উচিত)
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "8498611182:AAGezPOian1S9IWHhto94WJlAkWBHSo8OKw";

// [FILTER] Blocked Keywords (Hosting, VPN, Proxy)
const BLOCKED_ISPS = [
    'amazon', 'google cloud', 'digitalocean', 'microsoft', 'azure', 
    'hetzner', 'ovh', 'alibaba', 'linode', 'vultr', 'm247', 
    'datacamp', 'zenlayer', 'host', 'vpn', 'proxy', 'tunnel',
    'tor exit', 'relay', 'colocation', 'server', 'dedi', 'performive'
];

// [MEDIATION TIERS]
// Tier 1: High eCPM Countries (Priority: Monetag)
const TIER_1_COUNTRIES = ['US', 'GB', 'CA', 'AU', 'DE', 'CH', 'NO', 'NZ', 'SE', 'FR', 'NL'];

// Tier 2: Mid eCPM (Mixed Priority)
const TIER_2_COUNTRIES = ['IT', 'ES', 'BE', 'DK', 'FI', 'AE', 'SA', 'SG', 'KR', 'JP', 'QA'];

// Tier 3: Rest of the World (Priority: OnClicka for Fill Rate)
// (Logic: If not Tier 1 and not Tier 2 -> Then Tier 3)

// ================= 2. DATABASE SETUP =================
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ [MongoDB] Connected to Adsovio Cluster"))
    .catch(err => console.error("❌ [MongoDB] Connection Failed:", err));

// Traffic Log Schema
const TrafficLogSchema = new mongoose.Schema({
    ip: String,
    country: String,
    tier: String,           // Tier 1, 2, or 3
    status: String,         // allowed / blocked
    ad_network: String,     // monetag / onclicka
    reason: String,         // why blocked or allowed
    risk_score: Number,
    is_vpn_leaked: Boolean, // true if allowed via 40% rule
    telegram_id: String,
    device_info: Object,    // Battery, Screen, etc.
    timestamp: { type: Date, default: Date.now }
});

const TrafficLog = mongoose.model('TrafficLog', TrafficLogSchema);

// ================= 3. MAXMIND & HELPERS =================
let cityLookup = null;
let asnLookup = null;

// Load Databases Async
async function loadDatabases() {
    try {
        if (fs.existsSync(DB_PATH_CITY) && fs.existsSync(DB_PATH_ASN)) {
            cityLookup = await maxmind.open(DB_PATH_CITY);
            asnLookup = await maxmind.open(DB_PATH_ASN);
            console.log("✅ [MaxMind] GeoIP Engine Loaded.");
        } else {
            console.error("❌ [Critical] DB files missing in /db folder!");
        }
    } catch (e) { console.error("DB Load Error:", e); }
}
loadDatabases();

// Telegram Data Validator (HMAC SHA256)
function verifyTelegramData(initData) {
    if (!initData) return { valid: false, reason: "no_data" };
    // টোকেন না থাকলে বাইপাস (Testing)
    if (TELEGRAM_BOT_TOKEN === "YOUR_TELEGRAM_BOT_TOKEN") return { valid: true, id: "bypass_mode" };

    try {
        const urlParams = new URLSearchParams(initData);
        const hash = urlParams.get('hash');
        urlParams.delete('hash');
        
        const dataString = Array.from(urlParams.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([key, val]) => `${key}=${val}`)
            .join('\n');
            
        const secret = crypto.createHmac('sha256', 'WebAppData').update(TELEGRAM_BOT_TOKEN).digest();
        const calculatedHash = crypto.createHmac('sha256', secret).update(dataString).digest('hex');
        
        if (calculatedHash === hash) {
            const user = JSON.parse(urlParams.get('user'));
            return { valid: true, id: user.id };
        }
        return { valid: false, reason: "hash_mismatch" };
    } catch (e) { return { valid: false, reason: "parse_error" }; }
}

// ================= 4. MIDDLEWARE =================
app.use(cors({ origin: '*' })); // প্রোডাকশনে আপনার ডোমেইন দিন
app.use(express.json());
app.use(requestIp.mw());
app.use(helmet());
app.use(morgan('tiny'));

// Rate Limit: 1 Minute / 50 Requests (Anti-Spam)
const limiter = rateLimit({ windowMs: 60 * 1000, max: 50 });
app.use('/api/', limiter);

// ================= 5. TRAFFIC ANALYSIS ENGINE =================
async function analyzeTraffic(req, inputData) {
    // DB ফেইল করলে বাইপাস (Revenue Loss ঠেকানো)
    if (!cityLookup || !asnLookup) return { status: 'allowed', ad_config: { priority: 'monetag' } };

    const clientIp = req.clientIp;
    const { 
        timezone, screen, webdriver, battery, 
        telegramInitData, platform 
    } = inputData;
    
    let status = 'allowed';
    let reason = 'organic';
    let tier = 'tier-3'; // Default Tier
    let country = 'UNK';
    let ipTimezone = 'UNK';
    let isVpnDetected = false;
    let telegramUserId = null;
    let riskScore = 0;

    try {
        // [A] TELEGRAM CHECK
        if (telegramInitData) {
            const tgCheck = verifyTelegramData(telegramInitData);
            if (!tgCheck.valid) {
                status = 'blocked'; reason = `tg_fraud (${tgCheck.reason})`; riskScore += 100;
            } else {
                telegramUserId = tgCheck.id;
            }
        }

        // [B] GEO LOOKUP
        const cityData = cityLookup.get(clientIp);
        const asnData = asnLookup.get(clientIp);
        if (cityData?.country) country = cityData.country.iso_code;
        if (cityData?.location) ipTimezone = cityData.location.time_zone;

        // [C] FRAUD DETECTION
        // 1. Hosting/VPN Check
        if (asnData?.autonomous_system_organization) {
            const org = asnData.autonomous_system_organization.toLowerCase();
            if (BLOCKED_ISPS.some(k => org.includes(k))) {
                isVpnDetected = true;
                reason = `vpn_hosting (${org})`;
                riskScore += 60;
            }
        }

        // 2. Timezone Mismatch
        if (!isVpnDetected && ipTimezone && timezone && timezone !== 'UNK') {
            if (ipTimezone !== timezone) {
                isVpnDetected = true;
                reason = 'timezone_mismatch';
                riskScore += 40;
            }
        }

        // 3. Bot Signals (No 40% Tolerance for Bots)
        if (webdriver || screen === '0x0' || screen === '1x1') {
            status = 'blocked'; reason = 'bot_automation'; riskScore += 100;
        }

        // 4. Phone Farm Check (100% Battery + Charging)
        if (battery && battery.level === 1 && battery.charging) {
            riskScore += 20; // Suspicious but not blocked immediately
        }

        // [D] THE 40% VPN LEAK RULE
        let isLeaked = false;
        if (status === 'allowed' && isVpnDetected) {
            // যদি VPN হয় কিন্তু হার্ডকোর বট না হয়
            const chance = Math.random() * 100; // 0-100
            
            if (chance <= 40) {
                // 40% Chance: ALLOW (Leak Traffic)
                status = 'allowed';
                isLeaked = true;
                console.log(`⚠️ [VPN ALLOWED] ${clientIp} (40% Rule applied)`);
            } else {
                // 60% Chance: BLOCK
                status = 'blocked';
                console.log(`🚫 [VPN BLOCKED] ${clientIp}`);
            }
        }

        // [E] TIER CALCULATION
        if (TIER_1_COUNTRIES.includes(country)) tier = 'tier-1';
        else if (TIER_2_COUNTRIES.includes(country)) tier = 'tier-2';
        else tier = 'tier-3'; // Rest of the World

        // [F] SMART MEDIATION STRATEGY (The Waterfall)
        let priorityNetwork = 'monetag';

        if (status === 'allowed') {
            if (tier === 'tier-1') {
                // Tier 1: 90% Monetag (High CPM)
                priorityNetwork = (Math.random() * 100 < 90) ? 'monetag' : 'onclicka';
            } else if (tier === 'tier-2') {
                // Tier 2: 60% Monetag, 40% OnClicka
                priorityNetwork = (Math.random() * 100 < 60) ? 'monetag' : 'onclicka';
            } else {
                // Tier 3: 20% Monetag, 80% OnClicka (Focus on Fill Rate)
                priorityNetwork = (Math.random() * 100 < 20) ? 'monetag' : 'onclicka';
            }
        } else {
            priorityNetwork = 'none';
        }

        // [G] LOGGING TO MONGODB (Async)
        const log = new TrafficLog({
            ip: clientIp, country, tier, status,
            reason, is_vpn_leaked: isLeaked,
            ad_network: priorityNetwork,
            telegram_id: telegramUserId,
            risk_score: riskScore,
            device_info: { battery, webdriver, screen, platform }
        });
        log.save().catch(e => console.error("Log Error:", e));

        // Return Final Decision
        return {
            status,
            country,
            tier,
            ad_config: { priority: priorityNetwork }
        };

    } catch (e) {
        console.error("Engine Error:", e);
        return { status: 'allowed', ad_config: { priority: 'monetag' } };
    }
}

// ================= 6. ROUTES =================
app.post('/api/v1/validate-traffic', async (req, res) => {
    const result = await analyzeTraffic(req, req.body);
    res.json(result);
});

// Health Check
app.get('/', (req, res) => {
    res.send("Adsovio Secure Engine v2.0 is Running...");
});

// ================= 7. SERVER START =================
app.listen(PORT, () => {
    console.log(`
    ################################################
    🚀 ADSOVIO BACKEND RUNNING ON PORT ${PORT}
    ------------------------------------------------
    🛡️ VPN Policy: 40% Allowed / 60% Blocked
    🌍 Tier System: 1 (Monetag), 3 (OnClicka)
    📊 Analytics: MongoDB Connected
    ################################################
    `);
});