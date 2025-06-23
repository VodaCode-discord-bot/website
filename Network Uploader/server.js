const express = require("express");
const multer = require("multer");
const session = require("express-session");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const os = require('os')
const si = require('systeminformation');
const { exec } = require('child_process');

// Controleer of de omgeving variabele SUBDOMAIN is ingesteld
const app = express();
const PORT = 3000; // Changed from 443 to 3000 to avoid permission errors
const SALT_ROUNDS = 12; // Good balance between security and performance
// Start de server

// Database bestanden
const DATA_DIR = "./data";
const SETTINGS_DIR = path.join(DATA_DIR, "settings");
const LOGS_DIR = path.join(DATA_DIR, "logs");
const HOME_DIR = os.homedir();
const UPLOAD_DIR = path.join(HOME_DIR, "desktop", "uploads")

console.log(UPLOAD_DIR)

const USERS_FILE = path.join(SETTINGS_DIR, "users.json");
const LOG_FILE = path.join(LOGS_DIR, "upload_log.txt");
const LOGIN_LOG_FILE = path.join(LOGS_DIR, "login_log.txt");
const FILES_DB = path.join(SETTINGS_DIR, "files.json");

// Initialiseer de bestandsstructuur
function initializeFileStructure() {
  // Maak directories aan als ze niet bestaan
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
  if (!fs.existsSync(SETTINGS_DIR)) fs.mkdirSync(SETTINGS_DIR);
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR);
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

  // Initialiseer bestanden met standaard inhoud indien ze niet bestaan
  if (!fs.existsSync(USERS_FILE)) {
    const defaultAdminPassword = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString("hex"); // Retrieve from environment or generate securely
    bcrypt.hash(defaultAdminPassword, SALT_ROUNDS).then(hashedPassword => {
      const defaultUsers = {
        "admin": hashedPassword
      };
      fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
      console.log("\x1b[32mAdmin account aangemaakt\x1b[0m");
    });
  }

  if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, "");
  if (!fs.existsSync(LOGIN_LOG_FILE)) fs.writeFileSync(LOGIN_LOG_FILE, "");
  if (!fs.existsSync(FILES_DB)) fs.writeFileSync(FILES_DB, JSON.stringify({ files: [] }));
}

// Roep de initialisatiefunctie aan
initializeFileStructure();

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false
});

// Strict limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  handler: (req, res) => {
    res.status(429).send(
      htmlWrapper(
        "Te veel pogingen",
        `
          <h1><center>⛔ Te veel pogingen!</center></h1>
          <p><center>Probeer het over een uur opnieuw.</center></p>
          <center>
            <a href="/login" class="back-link">🏠 Terug naar login</a>
          </center>
        `
      )
    );
  }
});

// Apply to routes
app.use('/api/', apiLimiter); // General API routes
app.use('/login', authLimiter); // Login endpoint
app.use('/adduser', authLimiter); // User creation endpoint


// Voeg deze functie toe naast de andere database functies
const cleanupExpiredLinks = () => {
  const db = readFilesDB();
  const beforeCount = db.files.length;
  db.files = db.files.filter((f) => Date.now() <= f.expires);

  if (beforeCount !== db.files.length) {
    saveFilesDB(db);
    const logEntry = `[CLEANUP] ${new Date().toLocaleString()} | ${
      beforeCount - db.files.length
    } verlopen links verwijderd\n`;
    fs.appendFileSync(LOG_FILE, logEntry);
  }
};

// Middleware setup
app.set('trust proxy', 'loopback'); // Voeg deze toe om de proxy te vertrouwen
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "secure-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: false, 
      maxAge: 24 * 60 * 60 * 1000 
    },
  })
);

// Bestandsdatabase functies
const readFilesDB = () => {
  try {
    return JSON.parse(fs.readFileSync(FILES_DB));
  } catch {
    return { files: [] };
  }
};

const saveFilesDB = (data) => {
  fs.writeFileSync(FILES_DB, JSON.stringify(data, null, 2));
};

// Initialisatie mappen
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "{}");

// Multer configuratie
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOAD_DIR, req.session.username);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});
const upload = multer({ storage });

// Authenticatie middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.username) return next();
  res.redirect("/login.html");
};

// Basis HTML template
const htmlWrapper = (title, content) => `
<html>
<head>
    <title>${title}</title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="/styles.css">
    <script src="/theme.js"></script>
</head>
<body>
    <button class="theme-toggle" onclick="toggleTheme()">☀️/🌙</button>
    <div class="upload-app">
        ${content}
    </div>
</body>
</html>
`;
app.get("/pc_2", isAuthenticated, (req, res) => {
    res.send(htmlWrapper("Pc 2",`<a href="https://nl.pcpartpicker.com/list/xmqHKq">PCPartPicker Part List</a>
<table class="pcpp-part-list">
  <thead>
    <tr>
      <th>Type</th>
      <th>Item</th>
      <th>Price</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="pcpp-part-list-type">CPU</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/ycGbt6/amd-ryzen-7-5700g-38-ghz-8-core-processor-100-100000263box">AMD Ryzen 7 5700G 3.8 GHz 8-Core Processor</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/ycGbt6/amd-ryzen-7-5700g-38-ghz-8-core-processor-100-100000263box">€155.00 @ Megekko</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">CPU Cooler</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/LQt9TW/deepcool-ag400-7589-cfm-cpu-cooler-r-ag400-bknnmn-g-1">Deepcool AG400 75.89 CFM CPU Cooler</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/LQt9TW/deepcool-ag400-7589-cfm-cpu-cooler-r-ag400-bknnmn-g-1">€35.85 @ Megekko</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Motherboard</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/7gxbt6/msi-b550-a-pro-atx-am4-motherboard-b550-a-pro">MSI B550-A PRO ATX AM4 Motherboard</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/7gxbt6/msi-b550-a-pro-atx-am4-motherboard-b550-a-pro">€99.99 @ Amazon Netherlands</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Memory</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/dqbTwP/gskill-ripjaws-v-32-gb-2-x-16-gb-ddr4-4000-cl18-memory-f4-4000c18d-32gvk">G.Skill Ripjaws V 32 GB (2 x 16 GB) DDR4-4000 CL18 Memory</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/dqbTwP/gskill-ripjaws-v-32-gb-2-x-16-gb-ddr4-4000-cl18-memory-f4-4000c18d-32gvk">€69.90 @ Amazon Netherlands</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Storage</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/JNTZxr/lexar-nq710-500-gb-m2-2280-pcie-40-x4-nvme-solid-state-drive-lnq710x500g-rnnnu">Lexar NQ710 500 GB M.2-2280 PCIe 4.0 X4 NVME Solid State Drive</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/JNTZxr/lexar-nq710-500-gb-m2-2280-pcie-40-x4-nvme-solid-state-drive-lnq710x500g-rnnnu">€37.90 @ Azerty</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Storage</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">Seagate IronWolf NAS 4 TB 3.5" 5400 RPM Internal Hard Drive</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">€103.90 @ Azerty</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Storage</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">Seagate IronWolf NAS 4 TB 3.5" 5400 RPM Internal Hard Drive</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">€103.90 @ Azerty</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Storage</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">Seagate IronWolf NAS 4 TB 3.5" 5400 RPM Internal Hard Drive</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">€103.90 @ Azerty</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Case</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/qTGkcf/cooler-master-case-for500kkn1">Cooler Master Force 500 ATX Mid Tower Case</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/qTGkcf/cooler-master-case-for500kkn1">€57.90 @ Megekko</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Power Supply</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/GdwmP6/corsair-rm650-2023-650-w-80-gold-certified-fully-modular-atx-power-supply-cp-9020280-na">Corsair RM650 (2023) 650 W 80+ Gold Certified Fully Modular ATX Power Supply</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/GdwmP6/corsair-rm650-2023-650-w-80-gold-certified-fully-modular-atx-power-supply-cp-9020280-na">€89.88 @ Amazon Netherlands</a>
      </td>
    </tr>
    <tr>
      <td class="pcpp-part-list-type">Case Fan</td>
      <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/cbmNnQ/corsair-rs120-728-cfm-120-mm-fans-3-pack-co-9050189-ww">Corsair RS120 72.8 CFM 120 mm Fans 3-Pack</a></td>
      <td class="pcpp-part-list-price">
        <a href="https://nl.pcpartpicker.com/product/cbmNnQ/corsair-rs120-728-cfm-120-mm-fans-3-pack-co-9050189-ww">€24.90 @ Amazon Netherlands</a>
      </td>
    </tr>
    <tr>
      <td></td>
      <td class="pcpp-part-list-price-note">Prices include shipping, taxes, rebates, and discounts</td>
      <td></td>
    </tr>
    <tr>
      <td></td>
      <td class="pcpp-part-list-total">Total</td>
      <td class="pcpp-part-list-total-price">€883.02</td>
    </tr>
    <tr>
      <td></td>
      <td class="pcpp-part-list-price-note">Generated by <a href="https://pcpartpicker.com">PCPartPicker</a> 2025-05-17 16:58 CEST+0200</td>
      <td></td>
    </tr>
  </tbody>
</table>
<head>
<style>
.pcpp-part-list {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    font-family: Arial, sans-serif;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.pcpp-part-list th {
    background-color: #3498db;
    color: white;
    text-align: left;
    padding: 12px;
}

.pcpp-part-list td {
    padding: 10px 12px;
    border-bottom: 1px solid #e0e0e0;
}

.pcpp-part-list-type {
    font-weight: bold;
    color: #2c3e50;
    white-space: nowrap;
}

.pcpp-part-list-item a {
    color: #2980b9;
    text-decoration: none;
}

.pcpp-part-list-item a:hover {
    text-decoration: underline;
}

.pcpp-part-list-price a {
    color: #27ae60;
    font-weight: bold;
}

.pcpp-part-list-price-note {
    font-size: 0.9em;
    color: #7f8c8d;
    padding: 8px 0;
}

.pcpp-part-list-total {
    font-weight: bold;
    background-color: #f8f9fa !important;
}

.pcpp-part-list-total-price {
    color: #e74c3c;
    font-weight: bold;
}

/* Zebra-striping voor rijen */
.pcpp-part-list tbody tr:nth-child(odd) {
    background-color: #f8f9fa;
}

.pcpp-part-list tbody tr:hover {
    background-color: #e8f4fc;
}
</style>
</head>`))
})
app.get("/pc", isAuthenticated, (req, res) => {
  	res.send(htmlWrapper("Pc 1", `
      <a href="https://nl.pcpartpicker.com/list/vDPW74">PCPartPicker Part List</a>
              <table class="pcpp-part-list">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Item</th>
                    <th>Price</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td class="pcpp-part-list-type">CPU</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/KwLwrH/amd-ryzen-9-5900x-37-ghz-12-core-processor-100-100000061wof">AMD Ryzen 9 5900X 3.7 GHz 12-Core Processor</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/KwLwrH/amd-ryzen-9-5900x-37-ghz-12-core-processor-100-100000061wof">€259.00 @ bol.</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">CPU Cooler</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/LQt9TW/deepcool-ag400-7589-cfm-cpu-cooler-r-ag400-bknnmn-g-1">Deepcool AG400 75.89 CFM CPU Cooler</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/LQt9TW/deepcool-ag400-7589-cfm-cpu-cooler-r-ag400-bknnmn-g-1">€35.85 @ Megekko</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Motherboard</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/JVJgXL/msi-b550-gaming-gen3-atx-am4-motherboard-b550-gaming-gen3">MSI B550 GAMING GEN3 ATX AM4 Motherboard</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/JVJgXL/msi-b550-gaming-gen3-atx-am4-motherboard-b550-gaming-gen3">€109.00 @ Amazon Netherlands</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Memory</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/G4MTwP/gskill-ripjaws-v-64-gb-4-x-16-gb-ddr4-3600-memory-f4-3600c18q-64gvk">G.Skill Ripjaws V 64 GB (4 x 16 GB) DDR4-3600 CL18 Memory</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/G4MTwP/gskill-ripjaws-v-64-gb-4-x-16-gb-ddr4-3600-memory-f4-3600c18q-64gvk">€125.85 @ Azerty</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Storage</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/V3yH99/lexar-nm710-1-tb-m2-2280-pcie-40-x4-nvme-solid-state-drive-lnm710x001t-rnnng">Lexar NM710 1 TB M.2-2280 PCIe 4.0 X4 NVME Solid State Drive</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/V3yH99/lexar-nm710-1-tb-m2-2280-pcie-40-x4-nvme-solid-state-drive-lnm710x001t-rnnng">€57.90 @ Megekko</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Storage</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">Seagate IronWolf NAS 4 TB 3.5" 5400 RPM Internal Hard Drive</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">€103.90 @ Azerty</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Storage</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">Seagate IronWolf NAS 4 TB 3.5" 5400 RPM Internal Hard Drive</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">€103.90 @ Azerty</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Storage</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">Seagate IronWolf NAS 4 TB 3.5" 5400 RPM Internal Hard Drive</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/6FQcCJ/seagate-ironwolf-nas-4-tb-35-5400-rpm-internal-hard-drive-st4000vn006">€103.90 @ Azerty</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Video Card</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/KXYmP6/asus-geforce-rtx-3060-12-gb-dual-oc-v2-video-card-dual-rtx3060-o12g-v2">Asus Dual GeForce RTX 3060 V2 OC Edition GeForce RTX 3060 12GB 12 GB Video Card</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/KXYmP6/asus-geforce-rtx-3060-12-gb-dual-oc-v2-video-card-dual-rtx3060-o12g-v2">€299.00 @ Amazon Netherlands</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Case</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/sBQypg/nanoxia-case-nxds3b">Nanoxia Deep Silence 3 ATX Mid Tower Case</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/sBQypg/nanoxia-case-nxds3b">€86.05 @ Amazon Netherlands</a>
                    </td>
                  </tr>
                  <tr>
                    <td class="pcpp-part-list-type">Power Supply</td>
                    <td class="pcpp-part-list-item"><a href="https://nl.pcpartpicker.com/product/YRJp99/corsair-rm750e-2023-750-w-80-gold-certified-fully-modular-atx-power-supply-cp-9020262-na">Corsair RM750e (2023) 750 W 80+ Gold Certified Fully Modular ATX Power Supply</a></td>
                    <td class="pcpp-part-list-price">
                      <a href="https://nl.pcpartpicker.com/product/YRJp99/corsair-rm750e-2023-750-w-80-gold-certified-fully-modular-atx-power-supply-cp-9020262-na">€114.90 @ Amazon Netherlands</a>
                    </td>
                  </tr>
                  <tr>
                    <td></td>
                    <td class="pcpp-part-list-price-note">Prices include shipping, taxes, rebates, and discounts</td>
                    <td></td>
                  </tr>
                  <tr>
                    <td></td>
                    <td class="pcpp-part-list-total">Total</td>
                    <td class="pcpp-part-list-total-price">€1399.25</td>
                  </tr>
                  <tr>
                    <td></td>
                    <td class="pcpp-part-list-price-note">Generated by <a href="https://pcpartpicker.com">PCPartPicker</a> 2025-05-11 11:52 CEST+0200</td>
                    <td></td>
                  </tr>
                </tbody>
              </table>
              <head>
              <style>
              .pcpp-part-list {
                  width: 100%;
                  border-collapse: collapse;
                  margin: 20px 0;
                  font-family: Arial, sans-serif;
                  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
              }

              .pcpp-part-list th {
                  background-color: #3498db;
                  color: white;
                  text-align: left;
                  padding: 12px;
              }

              .pcpp-part-list td {
                  padding: 10px 12px;
                  border-bottom: 1px solid #e0e0e0;
              }

              .pcpp-part-list-type {
                  font-weight: bold;
                  color: #2c3e50;
                  white-space: nowrap;
              }

              .pcpp-part-list-item a {
                  color: #2980b9;
                  text-decoration: none;
              }

              .pcpp-part-list-item a:hover {
                  text-decoration: underline;
              }

              .pcpp-part-list-price a {
                  color: #27ae60;
                  font-weight: bold;
              }

              .pcpp-part-list-price-note {
                  font-size: 0.9em;
                  color: #7f8c8d;
                  padding: 8px 0;
              }

              .pcpp-part-list-total {
                  font-weight: bold;
                  background-color: #f8f9fa !important;
              }

              .pcpp-part-list-total-price {
                  color: #e74c3c;
                  font-weight: bold;
              }

              /* Zebra-striping voor rijen */
              .pcpp-part-list tbody tr:nth-child(odd) {
                  background-color: #f8f9fa;
              }

              .pcpp-part-list tbody tr:hover {
                  background-color: #e8f4fc;
              }
       </style>
    </head>`))
})

app.get("/pc_selector", isAuthenticated, (req,res) => {
  res.send(htmlWrapper(
    "Pc Selector", `
      <h1 class="welcome-header">Welkom ${req.session.username}!</h1>
        <div class="auth-container">
        <div class="auth-options">
          <a href="/pc" class="auth-btn">💻 PC 1</a>
          <a href="/pc_2" class="auth-btn">💻 PC 2</a>
          <a href="/logout" class="auth-btn logout">🚪 Uitloggen</a>
        </div>
      </div>
    `
  ))
})

// Routes
app.get("/", isAuthenticated, (req, res) => {
  res.send(
    htmlWrapper(
      "Uploader",
      `
        <h1 class="welcome-header">Welkom ${req.session.username}!</h1>
        
        <div class="file-selector-container">
            <div class="file-selector-header" onclick="toggleFileList()">
                📁 Geselecteerde bestanden: <span class="file-counter" id="fileCount">0</span>
            </div>
            <div class="file-list-container" id="fileList"></div>
            <button class="action-button add-button" onclick="document.getElementById('fileInput').click()">
                ➕ Bestanden toevoegen
            </button>
        </div>

        <div id="progressContainer" class="hidden">
            <div class="progress-bar">
                <div id="progressBar" class="progress-fill"></div>
            </div>
            <div id="progressText" class="progress-text">0%</div>
        </div>

        <div id="uploadError" class="error-message hidden"></div>
        
        <button class="action-button primary-button" onclick="startUpload()">
            <center>📤 Uploaden</center>
        </button>

        <input type="file" id="fileInput" multiple hidden>

        <div class="navigation-links">
            <a href="/myuploads" class="nav-link">📂 Mijn Uploads</a>
            <a href="/logout" class="nav-link">🚪 Uitloggen</a>\
            <a href="/pc_selector" class="nav-link">💻 PC Selector</a>
            ${
              req.session.username === "admin"
                ? '<a href="/nas-dashboard" class="nav-link">🗄️ NAS Beheer</a>'
                : ""
            }
            ${
              req.session.username === "admin"
                ? '<a href="/admin" class="nav-link">📋 Adminpaneel</a>'
                : ""
            }
        </div>

        <script>
            const fileInput = document.getElementById('fileInput');
            const fileList = document.getElementById('fileList');
            const fileCount = document.getElementById('fileCount');
            let files = [];

            // Bestandsselectie handler
            fileInput.addEventListener('change', (e) => {
                files = [...files, ...Array.from(e.target.files)];
                updateFileList();
                e.target.value = '';
            });

            function updateFileList() {
                fileList.innerHTML = files.map((file, index) => \`
                    <div class="file-item">
                        <span>\${file.name}</span>
                        <span class="file-size">(\${formatFileSize(file.size)})</span>
                        <button class="remove-button" onclick="removeFile(\${index})">❌</button>
                    </div>
                \`).join('');
                fileCount.textContent = files.length;
            }

            function formatFileSize(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            function removeFile(index) {
                files.splice(index, 1);
                updateFileList();
                const newFileList = new DataTransfer();
                files.forEach(file => newFileList.items.add(file));
                fileInput.files = newFileList.files;
            }

            function startUpload() {
                const errorDiv = document.getElementById('uploadError');
                const progressBar = document.getElementById('progressBar');
                const progressText = document.getElementById('progressText');
                const progressContainer = document.getElementById('progressContainer');

                errorDiv.classList.add('hidden');
                progressBar.style.width = '0%';
                progressText.textContent = '0%';
                progressContainer.classList.remove('hidden');

                if (files.length === 0) {
                    showError('Selecteer eerst bestanden!');
                    progressContainer.classList.add('hidden');
                    return;
                }

                const existingFiles = [];
                files.forEach(file => {
                    if (confirm(\`Bestand "\${file.name}" bestaat mogelijk al. Oude versie wordt overschreven. Doorgaan?\`)) {
                        existingFiles.push(file);
                    }
                });

                if (existingFiles.length === 0) return;

                const xhr = new XMLHttpRequest();
                const formData = new FormData();
                existingFiles.forEach(file => formData.append('files', file));

                xhr.upload.addEventListener('progress', (e) => {
                    if (e.lengthComputable) {
                        const percent = Math.round((e.loaded / e.total) * 100);
                        progressBar.style.width = \`\${percent}%\`;
                        progressText.textContent = \`\${percent}% voltooid\`;
                    }
                });

                xhr.addEventListener('load', () => {
                    if (xhr.status === 200) {
                        alert('✅ Upload voltooid!');
                        files = files.filter(f => !existingFiles.includes(f));
                        updateFileList();
                    } else {
                        showError(xhr.responseText || 'Upload mislukt');
                    }
                    progressContainer.classList.add('hidden');
                });

                xhr.addEventListener('error', () => {
                    showError('Netwerkfout');
                    progressContainer.classList.add('hidden');
                });

                xhr.open('POST', '/upload');
                xhr.send(formData);
            }

            function showError(message) {
                const errorDiv = document.getElementById('uploadError');
                errorDiv.textContent = \`❌ \${message}\`;
                errorDiv.classList.remove('hidden');
            }

            function toggleFileList() {
                fileList.classList.toggle('visible');
            }
        </script>
    `
    )
  );
});

// File upload endpoint
app.post("/upload", isAuthenticated, upload.array("files"), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).send("Geen bestanden ontvangen");
    }

    // Log the upload
    const logEntry = `[UPLOAD] ${new Date().toLocaleString()} | ${
      req.session.username
    } | ${req.files.length} bestanden\n`;
    fs.appendFileSync(LOG_FILE, logEntry);

    res.sendStatus(200);
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).send("Upload mislukt");
  }
});

// Routes
app.get("/myuploads", isAuthenticated, (req, res) => {
  cleanupExpiredLinks(); // Verwijder verlopen links

  const userDir = path.join(UPLOAD_DIR, req.session.username);
  const files = fs.existsSync(userDir) ? fs.readdirSync(userDir) : [];
  const db = readFilesDB();
  const filesDB = readFilesDB().files.filter(
    (f) => f.user === req.session.username
  );

  // Filter alleen niet-verlopen links voor deze gebruiker
  const validLinks = db.files.filter(
    (f) => f.user === req.session.username && Date.now() < f.expires
  );

  res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Mijn Uploads</title>
            <link rel="stylesheet" href="/styles.css">
            <script src="/theme.js"></script>
        </head>
        <body>
            <div class="navigation-links">
                <a href="/" class="back-link">🏠 Terug naar hoofdpagina</a>
                <h1>Mijn Bestanden</h1>
                
                ${
                  files.length === 0
                    ? "<p>Nog geen bestanden geüpload</p>"
                    : `<div class="file-grid">
                        ${files
                          .map((file) => {
                            const filePath = path.join(userDir, file);
                            const links = validLinks.filter(
                              (f) => f.filename === file
                            );

                            return `
                                <div class="file-card">
                                    <div class="file-info">
                                        <span class="file-name">${file}</span>
                                        <span class="file-size">${formatFileSize(
                                          fs.statSync(filePath).size
                                        )}</span>
                                    </div>
                                    
                                    <div class="file-actions">
                                    <center>
                                        <button onclick="generateLink('${file}')" class="action-btn generate-btn">
                                            Link maken
                                        </button>
                                        <button onclick="deleteFile('${file}')" class="action-btn delete-btn">
                                            Verwijderen
                                        </button>
                                    </center>
                                    </div>

                                    ${
                                      links.length > 0
                                        ? `
                                        <div class="links-list">
                                            ${links
                                              .map(
                                                (link) => `
                                                <div class="link-row">
                                                    <input type="text" value="${
                                                      req.headers.host
                                                    }/download/${
                                                  link.token
                                                }" readonly>
                                                    <button onclick="copyLink('${
                                                      link.token
                                                    }')" class="copy-btn">Kopiëren</button>
                                                    <span>Geldig voor: ${Math.round(
                                                      (link.expires -
                                                        Date.now()) /
                                                        3600000
                                                    )} uur</span>
                                                </div>
                                            `
                                              )
                                              .join("")}
                                        </div>
                                    `
                                        : ""
                                    }
                                </div>
                            `;
                          })
                          .join("")}
                    </div>`
                }
            </div>

            <script>
                async function generateLink(filename) {
                // Controleer eerst of er al een link bestaat
                const response = await fetch('/check-link/' + encodeURIComponent(filename));
                const { hasActiveLink } = await response.json();
                
                if (hasActiveLink) {
                    return alert('Dit bestand heeft al een actieve downloadlink!');
                }

                // Get hours from user
                const hours = prompt('Hoeveel uur moet de link geldig zijn? (Maximaal 24 uur)', '1');
                if (hours === null) return; // User cancelled
                
                const hoursNum = Number(hours);
                if (isNaN(hoursNum)) {
                    return alert('Voer een geldig aantal uur in');
                }
                if (hoursNum > 24) {
                    return alert('Links kunnen maximaal 24 uur geldig zijn');
                }
                if (hoursNum < 1) {
                    return alert('Links moeten minimaal 1 uur geldig zijn');
                }
                        
                try {
                    const response = await fetch('/generate-link/' + encodeURIComponent(filename), {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ hours: parseInt(hours) || 24 })
                    });
                    
                    if (response.ok) {
                        location.reload();
                    } else {
                        const error = await response.json();
                        throw new Error(error.error || 'Fout bij aanmaken link');
                    }
                } catch (error) {
                    alert(error.message);
                }
            }

                // Link kopiëren
                function copyLink(token) {
                    const link = \`http://${
                      req.headers.host
                    }/download/\${token}\`;
                    navigator.clipboard.writeText(link)
                        .then(() => alert('Link gekopieerd!'))
                        .catch(() => prompt('Kopieer handmatig:', link));
                }

                // Bestand verwijderen
                async function deleteFile(filename) {
                    if (confirm('Weet je zeker dat je "' + filename + '" wilt verwijderen?')) {
                        try {
                            const response = await fetch('/delete/' + encodeURIComponent(filename), {
                                method: 'DELETE'
                            });
                            if (response.ok) location.reload();
                            else throw new Error('Verwijderen mislukt');
                        } catch (error) {
                            alert(error.message);
                        }
                    }
                }
            </script>
        </body>
        </html>
    `);
});

function hasActiveLink(filename, user) {
  cleanupExpiredLinks(); // Eerst opschonen
  const db = readFilesDB();
  return db.files.some(
    (f) => f.filename === filename && f.user === user && Date.now() < f.expires
  );
}

app.get("/check-link/:filename", isAuthenticated, (req, res) => {
  const { filename } = req.params;
  res.json({
    hasActiveLink: hasActiveLink(filename, req.session.username),
  });
});

// Download link generatie
app.post("/generate-link/:filename", isAuthenticated, (req, res) => {
  try {
    const { filename } = req.params;
    const user = req.session.username;
    const filePath = path.join(UPLOAD_DIR, user, filename);

    // Controleer of bestand bestaat
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Bestand niet gevonden" });
    }

    // Controleer of er al een actieve link is
    if (hasActiveLink(filename, user)) {
      return res.status(400).json({
        error: "Dit bestand heeft al een actieve downloadlink",
      });
    }

    // Genereer nieuwe link
    const token = crypto.randomBytes(16).toString("hex");
    const hours = req.body.hours || 24;
    const expires = Date.now() + hours * 3600000;

    // Update database
    const db = readFilesDB();
    db.files.push({ token, filename, user, expires });
    saveFilesDB(db);

    // Logging
    const logEntry = `[LINK] ${new Date().toLocaleString()} | ${user} | ${filename} | ${hours}u\n`;
    fs.appendFileSync(LOG_FILE, logEntry);

    res.json({
      link: `http://${req.headers.host}/download/${token}`,
      expires: new Date(expires).toLocaleString(),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Bestand downloaden
app.get("/download/:token", (req, res) => {
  cleanupExpiredLinks(); // Eerst opschonen

  const db = readFilesDB();
  const link = db.files.find((f) => f.token === req.params.token);

  if (!link) {
    return res.status(404).send("Link is ongeldig of verwijderd");
  }

  if (Date.now() > link.expires) {
    // Verwijder de verlopen link
    const db = readFilesDB();
    db.files = db.files.filter((f) => f.token !== req.params.token);
    saveFilesDB(db);

    return res.status(410).send("Link is verlopen en is verwijderd");
  }

  const filePath = path.join(UPLOAD_DIR, link.user, link.filename);
  res.download(filePath, link.filename);
});

// Bestand verwijderen
app.delete("/delete/:filename", isAuthenticated, (req, res) => {
  const userDir = path.join(UPLOAD_DIR, req.session.username);
  const filePath = path.join(userDir, req.params.filename);

  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      // Verwijder gerelateerde links
      const db = readFilesDB();
      db.files = db.files.filter((f) => f.filename !== req.params.filename);
      saveFilesDB(db);
      return res.sendStatus(200);
    }
    res.status(404).send("Bestand niet gevonden");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + " " + sizes[i];
}

app.get("/admin", isAuthenticated, (req, res) => {
  if (req.session.username !== "admin") {
    return res.send(
      htmlWrapper(
        "Geen toegang",
        `
            <h1><center>⛔ Geen toegang!</center></h1>
            <p><center>Alleen voor administrators.</center></p>
            <a href="/" class="back-link"><center>Terug naar Home</center></a>
        `
      )
    );
  }

  // Verbeterde log-bestand verwerking
  const readLogFile = (filePath) => {
    try {
      if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, ""); // Maak bestand aan als het niet bestaat
        return "Logbestand is leeg";
      }
      const content = fs.readFileSync(filePath, "utf-8");
      return content || "Logbestand is leeg";
    } catch (error) {
      console.error(`Fout bij lezen ${filePath}:`, error);
      return `Fout bij laden logs: ${error.message}`;
    }
  };

  // Bereken schijfruimte gebruik
  const getUploadsSize = () => {
    let totalSize = 0;
    if (fs.existsSync(UPLOAD_DIR)) {
      fs.readdirSync(UPLOAD_DIR).forEach((user) => {
        const userDir = path.join(UPLOAD_DIR, user);
        if (fs.statSync(userDir).isDirectory()) {
          fs.readdirSync(userDir).forEach((file) => {
            totalSize += fs.statSync(path.join(userDir, file)).size;
          });
        }
      });
    }
    return formatFileSize(totalSize);
  };

  function getFileLength() {
    let fileCount = 0;
    // Count files in uploads directory (with user subdirectories)
    if (fs.existsSync(UPLOAD_DIR)) {
      fs.readdirSync(UPLOAD_DIR).forEach((user) => {
        const userDir = path.join(UPLOAD_DIR, user);
        if (fs.statSync(userDir).isDirectory()) {
          fileCount += fs.readdirSync(userDir).length;
        }
      });
    }
    return fileCount;
  }

  res.send(
    htmlWrapper(
      "Admin Paneel",
      `
      <div class="admin-container">
        <div class="stats-section">
          <center>
            <h3>📊 Statistieken</h3>
            <p>Totaal schijfgebruik: ${getUploadsSize()}</p>
            <p>Totaal aantal bestanden: ${getFileLength()}</p>
            <p>Totaal Aantal gebruikers: ${
              Object.keys(JSON.parse(fs.readFileSync(USERS_FILE))).length
            }</p>
          </center>
        </div>
  
        <div class="log-section">
          <h2><center>📋 Uploadlog</center></h2>
          <div class="log-container">
            <pre>${readLogFile(LOG_FILE)}</pre>
          </div>
          <center>
            <button onclick="cleanupLog('upload')" class="cleanup-btn">
              🗑️ Uploadlog opschonen
            </button>
          </center>
        </div>
        
        <div class="log-section">
          <h2><center>🔑 Inloglogboek</center></h2>
          <div class="log-container" id="loginLogContainer">
            <pre>${readLogFile(LOGIN_LOG_FILE)}</pre>
          </div>
          <center>
            <button onclick="cleanupLog('login')" class="cleanup-btn">
              🗑️ Inloglog opschonen
            </button>
          </center>
        </div>

        <div class="cleanup-section">
          <center>
            <h2>🧹 Bestanden opschonen</h2>
            <button onclick="cleanupFiles('expired')" class="cleanup-btn danger">
              🔥 Verlopen bestanden verwijderen
            </button>
            <button onclick="cleanupFiles('all')" class="cleanup-btn danger">
              💣 ALLE bestanden verwijderen
            </button>
            <p class="warning">⚠️ Deze acties kunnen niet ongedaan worden gemaakt!</p>
          </center>
        </div>
  
        <div class="admin-actions">
        <center>
          <a href="/adduser.html" class="admin-link">👤 Gebruiker toevoegen</a>
          <a href="/" class="admin-link">🏠 Terug naar Home</a>
        </center>
        </div>
      </div>

      <script>
        let autoScrollEnabled = true;

        function setupLogContainer(container) {
          // Scroll naar beneden bij initialisatie
          container.scrollTop = container.scrollHeight;
          
          // Voeg scroll event listener toe
          container.addEventListener('scroll', function() {
            // Bepaal of gebruiker naar boven heeft gescrolled
            const threshold = 20; // pixels buffer
            autoScrollEnabled = 
              this.scrollTop + this.clientHeight >= this.scrollHeight - threshold;
          });
        }

        function scrollToBottom() {
          if (!autoScrollEnabled) return;
          
          const containers = document.querySelectorAll('.log-container');
          containers.forEach(container => {
            container.scrollTo({
              top: container.scrollHeight,
              behavior: 'smooth'
            });
          });
        }

        // Initialisatie
        document.addEventListener('DOMContentLoaded', () => {
          // Setup alle containers
          document.querySelectorAll('.log-container').forEach(setupLogContainer);
          
          // Eerste scroll
          scrollToBottom();
          
          // Controleer periodiek (voor nieuwe logs)
          setInterval(scrollToBottom, 1000);
        });

        async function cleanupLog(logType) {
          try {
            if (!confirm(\`Weet u zeker dat u het \${logType}-logboek wilt leegmaken?\`)) return;
            
            const endpoint = logType === 'upload' ? '/delete-log' : '/delete-login-log';
            const response = await fetch(endpoint, {
              method: 'DELETE',
              headers: {
                'Accept': 'application/json'
              }
            });

            if (!response.ok) {
              const error = await response.json();
              throw new Error(error.error || 'Opschonen mislukt');
            }

            const result = await response.json();
            alert(result.message || 'Log succesvol geleegd');
            location.reload();
          } catch (error) {
            console.error('Cleanup error:', error);
            alert('Fout: ' + error.message);
          }
        }

        async function cleanupFiles(cleanupType) {
          const action = cleanupType === 'all' 
            ? 'ALLE geüploade bestanden' 
            : 'alleen bestanden zonder actieve links';
          
          if (!confirm('WAARSCHUWING: Dit verwijdert ' + action + '. Doorgaan?')) {
            return;
          }
          
          try {
            const response = await fetch('/cleanup-files', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ cleanupType })
            });
            
            if (response.ok) {
              const result = await response.json();
              alert('Succes! ' + result.deletedCount + ' bestanden verwijderd.');
              location.reload();
            } else {
              const error = await response.json();
              throw new Error(error.error || 'Opschonen mislukt');
            }
          } catch (error) {
            alert('Fout: ' + error.message);
          }
        }
      </script>
    `
    )
  );
});

// NAS Dashboard UI
app.get('/nas-dashboard', isAuthenticated, (req, res) => {
  if (req.session.username !== "admin") {
    return res.send(
      htmlWrapper(
        "Geen toegang",
        `
            <h1><center>⛔ Geen toegang!</center></h1>
            <p><center>Alleen voor administrators.</center></p>
            <a href="/" class="back-link"><center>Terug naar Home</center></a>
        `
      )
    );
  }
  res.send(htmlWrapper(
    "NAS Dashboard",
    `
    <div class="nas-container">
      <div class="nas-section">
        <h2><center>💾 Storage Overzicht</center></h2>
        <div id="storageStats"></div>
      </div>
      
      <div class="nas-section">
        <h2><center>📂 ZFS Pools</center></h2>
        <div id="zfsPools"></div>
        <button onclick="showCreatePoolModal()" class="action-button">
          ➕ Nieuwe Pool Maken
        </button>
      </div>
      
      <div class="nas-section">
        <h2><center>🔗 SMB Shares</center></h2>
        <div id="smbShares"></div>
        <button onclick="showCreateShareModal()" class="action-button">
          ➕ Nieuwe Share Maken
        </button>
      </div>
    </div>

    <!-- Modals -->
    <div id="createPoolModal" class="modal hidden">
      <div class="modal-content">
        <h3>Nieuwe ZFS Pool</h3>
        <label>Pool Naam: <input type="text" id="poolName"></label>
        <label>RAID Niveau:
          <select id="raidLevel">
            <option value="mirror">Mirror</option>
            <option value="raidz">RAIDZ</option>
            <option value="raidz2">RAIDZ2</option>
          </select>
        </label>
        <div id="diskSelection"></div>
        <button onclick="createPool()">Aanmaken</button>
        <button onclick="closeModal('createPoolModal')">Annuleren</button>
      </div>
    </div>
    
    <div id="createShareModal" class="modal hidden">
      <div class="modal-content">
        <h3>Nieuwe SMB Share</h3>
        <label>Share Naam: <input type="text" id="shareName"></label>
        <label>Pad: <input type="text" id="sharePath"></label>
        <button onclick="createShare()">Aanmaken</button>
        <button onclick="closeModal('createShareModal')">Annuleren</button>
      </div>
    </div>

    <script>
      async function loadNASData() {
        try {
          // Laad storagegegevens
          const storageRes = await fetch('/api/storage');
          const storageData = await storageRes.json();
          
          // Render storage overzicht
          document.getElementById('storageStats').innerHTML = \`
            <div class="storage-grid">
              \${storageData.partitions.map(part => \`
                <div class="storage-card">
                  <h4>\${part.fs}</h4>
                  <div class="progress-bar-drives">
                    <div class="progress-fill" style="width: \${(part.used / part.size * 100).toFixed(1)}%"></div>
                  </div>
                  <p>\${formatBytes(part.used)} / \${formatBytes(part.size)}</p>
                </div>
              \`).join('')}
            </div>
          \`;

          // Update de SMB share creatie modal
          document.getElementById('createShareModal').innerHTML = \`\
            <div class="modal-content">
              <span class="close" onclick="closeModal('createShareModal')">&times;</span>
              <h3>Nieuwe SMB Share</h3>
              
              <div class="form-group">
                <label for="shareName">Share Naam:</label>
                <input type="text" id="shareName" required>
              </div>
              
              <div class="form-group">
                <label>Pad Bron:</label>
                <div class="source-selector">
                  <button class="source-btn active" data-type="pool" onclick="setSourceType('pool')">ZFS Pool</button>
                  <button class="source-btn" data-type="custom" onclick="setSourceType('custom')">Aangepast Pad</button>
                </div>
              </div>
              
              <div id="poolSource" class="source-section">
                <label for="poolSelect">Selecteer ZFS Pool:</label>
                <select id="poolSelect">
                  \${storageData.zfsPools.map(pool => \`\
                    <option value="\${pool.mountpoint || '/' + pool.name}">
                      \${pool.name} (\${pool.size})
                    </option>
                  \`\).join('')}
                </select>
              </div>
              
              <div id="customSource" class="source-section hidden">
                <label for="customPath">Aangepast Pad:</label>
                <input type="text" id="customPath" placeholder="/pad/naar/directory">
              </div>
              
              <button class="submit-btn" onclick="createShare()">Aanmaken</button>
            </div>
          \`\;
                    
          // Render ZFS pools
          document.getElementById('zfsPools').innerHTML = \`
            <table class="zfs-table">
              <tr>
                <th>Naam</th>
                <th>Grootte</th>
                <th>Gebruikt</th>
                <th>Status</th>
                <th>Acties</th>
              </tr>
              \${storageData.zfsPools.map(pool => \`
                <tr>
                  <td>\${pool.name}</td>
                  <td>\${pool.size}</td>
                  <td>\${pool.alloc}</td>
                  <td><span class="status-\${pool.health.toLowerCase()}">\${pool.health}</span></td>
                  <td>
                    <button onclick="showPoolStatus('\${pool.name}')">Status</button>
                    <button onclick="deletePool('\${pool.name}')">Verwijder</button>
                  </td>
                </tr>
              \`).join('')}
            </table>
          \`;
          
          // Render schijven voor pool creatie
          // Vervang het diskSelection gedeelte in de /nas-dashboard route
          document.getElementById('diskSelection').innerHTML = \`
            <h4>Selecteer Schijven:</h4>
            \${storageData.disks.length > 0 
              ? storageData.disks.map(disk => \`
                  <div class="disk-option">
                    <input type="checkbox" id="disk-\${disk.name}" name="disks" value="/dev/\${disk.name}">
                    <label for="disk-\${disk.name}">
                      \${disk.name} - \${formatBytes(disk.size)}
                    </label>
                  </div>
                \`).join('') 
              : '<p class="no-disks">Geen beschikbare schijven gevonden</p>'}
          \`;
          
          // Laad SMB shares
          const sharesRes = await fetch('/api/smb/shares');
          const shares = await sharesRes.json();
          
          // Render SMB shares
          document.getElementById('smbShares').innerHTML = \`
            <ul class="share-list">
              \${shares.map(share => \`
                <li>
                  <strong>\${share.name}</strong>: \\\\\\\\\${window.location.hostname}\\\\\\\\ \${share.name}
                  <button onclick="deleteShare('\${share.name}')">Verwijder</button>
                </li>
              \`).join('')}
            </ul>
          \`;
          
        } catch (error) {
          console.error('Fout bij laden NAS data:', error);
        }
      }
      
      function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
      }
      
      function showCreatePoolModal() {
        document.getElementById('createPoolModal').classList.remove('hidden');
      }
      
      function showCreateShareModal() {
        document.getElementById('createShareModal').classList.remove('hidden');
      }
      
      function closeModal(id) {
        document.getElementById(id).classList.add('hidden');
      }
      
      async function createPool() {
        const name = document.getElementById('poolName').value;
        const raidLevel = document.getElementById('raidLevel').value;
        const disks = Array.from(document.querySelectorAll('input[name="disks"]:checked'))
          .map(disk => disk.value);
        
        if (!name || disks.length === 0) {
          alert('Vul alle velden in');
          return;
        }
        
        try {
          const response = await fetch('/api/zfs/create-pool', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, devices: disks, raidLevel })
          });
          
          if (response.ok) {
            alert('Pool succesvol aangemaakt!');
            closeModal('createPoolModal');
            loadNASData();
          } else {
            const error = await response.json();
            throw new Error(error.error);
          }
        } catch (error) {
          alert('Fout: ' + error.message);
        }
      }
      
      async function deletePool(name) {
        if (!confirm(\`Weet u zeker dat u pool "\${name}" wilt verwijderen?\`)) return;
        
        try {
          await fetch(\`/api/zfs/destroy-pool/\${name}\`, { method: 'DELETE' });
          alert('Pool verwijderd!');
          loadNASData();
        } catch (error) {
          alert('Fout: ' + error.message);
        }
      }
      
      async function showPoolStatus(name) {
        try {
          const response = await fetch(\`/api/zfs/pool-status/\${name}\`);
          const status = await response.text();
          alert(\`Status van pool \${name}:\\n\\n\${status}\`);
        } catch (error) {
          alert('Fout: ' + error.message);
        }
      }
      
      function setSourceType(type) {
        document.querySelectorAll('.source-btn').forEach(btn => {
          btn.classList.toggle('active', btn.dataset.type === type);
        });
        
        document.getElementById('poolSource').classList.toggle('hidden', type !== 'pool');
        document.getElementById('customSource').classList.toggle('hidden', type !== 'custom');
      }

      async function createShare() {
        const name = document.getElementById('shareName').value;
        let path = '';
        
        if (document.querySelector('.source-btn[data-type="pool"].active')) {
          path = document.getElementById('poolSelect').value;
        } else {
          path = document.getElementById('customPath').value;
        }
        
        if (!name || !path) {
          alert('Vul alle velden in');
          return;
        }
        
        try {
          const response = await fetch('/api/smb/create-share', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, path })
          });
          
          if (response.ok) {
            alert('Share succesvol aangemaakt!');
            closeModal('createShareModal');
            loadNASData();
          } else {
            const error = await response.json();
            throw new Error(error.error);
          }
        } catch (error) {
          alert('Fout: ' + error.message);
        }
      }
      
      // Laad data bij het openen van de pagina
      document.addEventListener('DOMContentLoaded', loadNASData);
    </script>
    `
  ));
});

// Pas je delete endpoint aan in server.js
app.delete("/delete-log", isAuthenticated, (req, res) => {
  try {
    fs.writeFileSync(LOG_FILE, ""); // Leeg het logbestand
    res.json({ success: true }); // Zorg dat je JSON teruggeeft
  } catch (error) {
    res.json(500).json({ error: error.message }); // Altijd JSON response
  }
});

// Update je bestaande delete endpoint
app.delete("/delete-login-log", isAuthenticated, (req, res) => {
  try {
    if (!fs.existsSync(LOGIN_LOG_FILE)) {
      // Return JSON error als bestand niet bestaat
      return res.json(404).json({ error: "Log file niet gevonden" });
    }

    fs.writeFileSync(LOGIN_LOG_FILE, "");
    res.json({ success: true, message: "Login log geleegd" });
  } catch (error) {
    console.error("Login log delete error:", error);
    // Zorg dat ALLE errors JSON retourneren
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Nieuwe route voor bestandsopschoning
app.post("/cleanup-files", isAuthenticated, (req, res) => {
  if (req.session.username !== "admin") {
    return res.status(403).json({ error: "Geen toegang" });
  }

  try {
    const { cleanupType } = req.body;
    let deletedCount = 0;

    if (cleanupType === "expired") {
      // Verwijder alleen bestanden waarvan alle links verlopen zijn
      const db = readFilesDB();
      const allFiles = fs.readdirSync(UPLOAD_DIR).flatMap((user) =>
        fs.readdirSync(path.join(UPLOAD_DIR, user)).map((file) => ({
          user,
          file,
          path: path.join(UPLOAD_DIR, user, file),
        }))
      );

      allFiles.forEach(({ user, file, path }) => {
        const hasActiveLinks = db.files.some(
          (f) =>
            f.filename === file && f.user === user && Date.now() < f.expires
        );

        if (!hasActiveLinks) {
          fs.unlinkSync(path);
          deletedCount++;
        }
      });
    } else if (cleanupType === "all") {
      // Verwijder alle uploads (behalve mappenstructuur)
      fs.readdirSync(UPLOAD_DIR).forEach((user) => {
        fs.readdirSync(path.join(UPLOAD_DIR, user)).forEach((file) => {
          fs.unlinkSync(path.join(UPLOAD_DIR, user, file));
          deletedCount++;
        });
      });
      fs.writeFileSync(FILES_DB, JSON.stringify({ files: [] }));
    }

    const logEntry = `[FILES CLEANUP] ${new Date().toLocaleString()} | ${
      req.session.username
    } | ${deletedCount} bestanden verwijderd\n`;
    fs.appendFileSync(LOG_FILE, logEntry);

    res.json({ success: true, deletedCount });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ZFS Management Module
class ZFSManager {
  static async listPools() {
    return new Promise((resolve) => {
      exec('zpool list -H -o name,size,alloc,free,health,mountpoint 2>/dev/null', (error, stdout) => {
        if (error) {
          console.log('Geen ZFS pools gevonden');
          resolve([]);
        } else {
          const pools = stdout.trim().split('\n').map(line => {
            const [name, size, alloc, free, health, mountpoint] = line.split(/\s+/);
            return { name, size, alloc, free, health, mountpoint };
          });
          resolve(pools);
        }
      });
    });
  }

  static async createPool(name, devices, raidLevel = 'mirror') {
    return new Promise((resolve, reject) => {
      exec(`sudo zpool create ${name} ${raidLevel} ${devices.join(' ')}`, (error) => {
        if (error) return reject(error);
        resolve();
      });
    });
  }

  static async destroyPool(name) {
    return new Promise((resolve, reject) => {
      exec(`sudo zpool destroy ${name}`, (error) => {
        if (error) return reject(error);
        resolve();
      });
    });
  }

  static async getPoolStatus(name) {
    return new Promise((resolve, reject) => {
      exec(`zpool status ${name}`, (error, stdout) => {
        if (error) return reject(error);
        resolve(stdout);
      });
    });
  }
}

// Storage Monitoring
// Vervang de /api/storage route door deze werkende versie
app.get('/api/storage', isAuthenticated, async (req, res) => {
  try {
    const partitions = await si.fsSize();
    const pools = await ZFSManager.listPools().catch(() => []);
    
    // Verbeterde schijfdetectie
    const getAvailableDisks = async () => {
      try {
        const blockDevices = await si.blockDevices();
        return blockDevices
          .filter(d => d.type === 'disk' && !d.mount && !d.fsType)
          .map(d => ({
            name: d.name,
            size: d.size,
            type: d.type,
            mount: d.mount
          }));
      } catch (error) {
        console.error('Schijfdetectie fout:', error);
        return [];
      }
    };

    const availableDisks = await getAvailableDisks();

    res.json({
      disks: availableDisks,
      partitions: partitions.map(p => ({
        fs: p.fs,
        size: p.size,
        used: p.used,
        available: p.available
      })),
      zfsPools: pools
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ZFS Management Endpoints
app.post('/api/zfs/create-pool', isAuthenticated, async (req, res) => {
  try {
    const { name, devices, raidLevel } = req.body;
    await ZFSManager.createPool(name, devices, raidLevel);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/zfs/destroy-pool/:name', isAuthenticated, async (req, res) => {
  try {
    const { name } = req.params;
    await ZFSManager.destroyPool(name);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/zfs/pool-status/:name', isAuthenticated, async (req, res) => {
  try {
    const { name } = req.params;
    const status = await ZFSManager.getPoolStatus(name);
    res.send(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SMB Share Management
// Update de SMBManager.createShare om directories aan te maken
class SMBManager {
  static async createShare(name, path) {
    return new Promise((resolve, reject) => {
      // Maak directory aan als deze niet bestaat
      if (!fs.existsSync(path)) {
        fs.mkdirSync(path, { recursive: true });
        console.log(`Directory aangemaakt: ${path}`);
      }
      
      const config = `
[${name}]
  path = ${path}
  browseable = yes
  writable = yes
  guest ok = yes
  create mask = 0777\n`;
      
      fs.appendFileSync('/etc/samba/smb.conf', config);
      exec('sudo systemctl restart smbd', (error) => {
        if (error) return reject(error);
        resolve();
      });
    });
  }
}
// Endpoint om SMB shares te beheren


app.post("/adduser", isAuthenticated, async (req, res) => { // Changed to async
  try {
    // 1. Verify admin privileges
    if (!req.session?.username === "admin") {
      logAdminActionAttempt(req.session?.username || 'unknown', 'unauthorized user creation attempt');
      return res.status(403).send(
        htmlWrapper(
          "Geen toegang",
          `
            <h1><center>⛔ Geen adminrechten!</center></h1>
            <center>
              <a href="/" class="nav-link">🏠 Terug naar hoofdpagina</a>
            </center>
          `
        )
      );
    }

    // 2. Validate input
    const { newuser, newpass } = req.body;
    if (!newuser?.trim() || !newpass?.trim()) {
      return res.status(400).send(
        htmlWrapper(
          "Ongeldig verzoek",
          `
            <p><center>❌ Gebruikersnaam en wachtwoord zijn verplicht.</center></p>
            <center>
              <a href="/admin" class="nav-link">← Terug naar adminpaneel</a>
            </center>
          `
        )
      );
    }

    // 3. Validate password strength
    if (newpass.length < 8) {
      return res.status(400).send(
        htmlWrapper(
          "Zwak wachtwoord",
          `
            <p><center>❌ Wachtwoord moet minimaal 8 tekens bevatten.</center></p>
            <center>
              <a href="/admin" class="nav-link">← Terug naar adminpaneel</a>
            </center>
          `
        )
      );
    }

    // 4. Load existing users
    const users = fs.existsSync(USERS_FILE) 
      ? JSON.parse(fs.readFileSync(USERS_FILE))
      : {};

    // 5. Check for existing user
    if (users[newuser]) {
      return res.status(400).send(
        htmlWrapper(
          "Gebruiker bestaat al",
          `
            <p><center>❌ Gebruiker '${escapeHtml(newuser)}' bestaat al.</center></p>
            <center>
              <a href="/admin" class="nav-link">← Terug naar adminpaneel</a>
            </center>
          `
        )
      );
    }

    // 6. Hash password and save user
    const hashedPassword = await bcrypt.hash(newpass, SALT_ROUNDS);
    users[newuser] = hashedPassword;
    
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    fs.appendFileSync(USERS_FILE, '\n'); // Add newline for better file reading

    // 7. Log the action
    logAdminAction(req.session.username, `added user: ${newuser}`);
    
    // 8. Send success response
    res.send(
      htmlWrapper(
        "Gebruiker toegevoegd",
        `
          <p><center>✅ Gebruiker '${escapeHtml(newuser)}' succesvol toegevoegd.</center></p>
          <center>
            <a href="/admin" class="nav-link">← Terug naar adminpaneel</a>
            <a href="/" class="nav-link">🏠 Terug naar hoofdpagina</a>
          </center>
        `
      )
    );

  } catch (error) {
    console.error('Error in /adduser:', error);
    logAdminAction(req.session?.username || 'unknown', `failed to add user: ${error.message}`);
    
    res.status(500).send(
      htmlWrapper(
        "Serverfout",
        `
          <p><center>❌ Er ging iets mis bij het toevoegen van de gebruiker.</center></p>
          <center>
            <a href="/admin" class="nav-link">← Terug naar adminpaneel</a>
          </center>
        `
      )
    );
  }
});

// Helper functions
function logAdminAction(adminUser, action) {
  const logEntry = `[ADMIN ACTION] ${new Date().toLocaleString()} | ${adminUser} | ${action}\n`;
  fs.appendFileSync(LOGIN_LOG_FILE, logEntry);
  console.log(`\x1b[34m[ADMIN]\x1b[0m ${logEntry.trim()}`);
}

function logAdminActionAttempt(user, action) {
  const logEntry = `[UNAUTHORIZED ADMIN ATTEMPT] ${new Date().toLocaleString()} | ${user} | ${action}\n`;
  fs.appendFileSync(LOGIN_LOG_FILE, logEntry);
  console.log(`\x1b[31m[ADMIN SECURITY]\x1b[0m ${logEntry.trim()}`);
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login.html"));
});

app.post("/login", async (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  try {
    // 1. Input validatie
    const { username, password } = req.body;

    if (!username || !password) {
      logFailedAttempt('empty credentials', ip);
      return sendLoginError(res, "Gebruikersnaam en wachtwoord zijn verplicht");
    }

    // 2. Laad gebruikersdata
    const users = fs.existsSync(USERS_FILE) 
      ? JSON.parse(fs.readFileSync(USERS_FILE))
      : {};

    // 3. Controleer gebruiker
    if (!users[username]) {

      logFailedAttempt(username, ip, 'unknown user');
      return sendLoginError(res, "Ongeldige gebruikersnaam of wachtwoord");
    }

    // 4. Wachtwoord verificatie
    const passwordMatch = await bcrypt.compare(password, users[username]);
    
    if (passwordMatch) {
      // 5. Sessie aanmaken
      req.session.regenerate((err) => {
        if (err) {
          console.error('\x1b[31m[SESSION ERROR]\x1b[0m', err);
          return res.status(500).send(
            htmlWrapper(
              "Sessie Fout",
              `<p><center>❌ Kon sessie niet aanmaken. Probeer opnieuw.</center></p>`
            )
          );
        }
    
        // Sessievariabelen instellen
        req.session.username = username;
        req.session.loginTime = Date.now();
        req.session.loginIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    
        // Sessie opslaan
        req.session.save((err) => {
          if (err) {
            console.error('\x1b[31m[SESSION SAVE ERROR]\x1b[0m', err);
            return res.status(500).send(
              htmlWrapper(
                "Sessie Fout",
                `<p><center>❌ Kon sessie niet opslaan. Probeer opnieuw.</center></p>`
              )
            );
          }
    
          // Succesvolle login loggen
          logSuccessfulLogin(username, ip);
    
          // Beveiligde redirect naar dashboard (voorkomt refresh issues)
          res.redirect('/dashboard');
        });
      });
    } else {
      console.log(`Wachtwoord mismatch voor ${username}`);
      logFailedAttempt(username, ip, 'wrong password');
      sendLoginError(res, "Ongeldige gebruikersnaam of wachtwoord");
    }

  } catch (error) {
    console.error('\x1b[31m[LOGIN ERROR]\x1b[0m', error); // Debug log
    fs.appendFileSync(LOGIN_LOG_FILE, `[ERROR] ${new Date().toLocaleString()} | ${error.message}\n`);
    res.status(500).send(
      htmlWrapper(
        "Serverfout",
        `<p><center>❌ Er ging iets mis tijdens het inloggen. Probeer later opnieuw.</center></p>`
      )
    );
  }
});

// Nieuwe dashboard route (beveiligd)
app.get("/dashboard", isAuthenticated, (req, res) => {
  if (!req.session.username) {
    return res.redirect("/login?error=session_expired");
  }
  
  res.send(htmlWrapper("Dashboard",
    `<div class="auth-container">
       <h2><center>Welkom ${escapeHtml(req.session.username)}</center></h2>
       <div class="auth-options">
         <a href="/" class="auth-btn">📂 Uploader</a>
         <a href="/pc_selector" class="auth-btn">💻 PC Selector</a>
         <a href="/logout" class="auth-btn logout">🚪 Uitloggen</a>
       </div>
     </div>`
  ));
});

// Verbeterde logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    // Clear cookie voor zekerheid
    res.clearCookie('connect.sid');
    res.redirect("/login?message=logout_success");
  });
});

// Helper functions
function logSuccessfulLogin(username, ip) {
  const prefix = username === "admin" ? "[ADMIN LOGIN] " : "[USER LOGIN] ";
  const logEntry = `${prefix}${new Date().toLocaleString()} | ${username} ingelogd vanaf ${ip}\n`;
  fs.appendFileSync(LOGIN_LOG_FILE, logEntry);
  console.log(`\x1b[32m[LOGIN]\x1b[0m ${logEntry.trim()}`);
}

function logFailedAttempt(username, ip, reason = '') {
  const isAdminAttempt = username.toLowerCase() === "admin";
  const type = isAdminAttempt ? "admin-poging" : "gebruiker";
  const failedEntry = `[FAILED] ${new Date().toLocaleString()} | Poging: ${username} (${type}) vanaf ${ip} ${reason ? '| Reden: ' + reason : ''}\n`;
  fs.appendFileSync(LOGIN_LOG_FILE, failedEntry);
  console.log(`\x1b[31m[FAILED LOGIN]\x1b[0m ${failedEntry.trim()}`);
}

function sendLoginError(res, message) {
  res.send(
    htmlWrapper(
      "Login Mislukt",
      `
        <h1><center>❌ Login mislukt!</center></h1>
        <p><center>${message}</center></p>
        <center>
          <a href="/login.html" class="nav-link">↻ Probeer opnieuw</a>
          <a href="/" class="nav-link">🏠 Terug naar hoofdpagina</a>
        </center>
      `
    )
  );
}

// Server start
app.listen(PORT, () => {
  console.log(`
==============================================
🚀 Server gestart op http://localhost:${PORT}
==============================================
`);
  // Voer direct een cleanup uit
  cleanupExpiredLinks();

  // Voer elk uur een cleanup uit
  setInterval(cleanupExpiredLinks, 3600000);
});