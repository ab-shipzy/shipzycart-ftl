/* apiEwbDetails — fetch e-way bill details from WhiteBooks by EWB number.
   v2: self-adapting API-key verification (matches any reasonable schema
   the LTL API may use for storing hashed keys in Firestore). */

const functions = require("firebase-functions");
const https = require("https");
const crypto = require("crypto");
const admin = require("firebase-admin");
try { admin.app(); } catch { admin.initializeApp(); }

const WB_HOSTS = {
  sandbox:    "apisandbox.whitebooks.in",
  production: "api.whitebooks.in",
};

function cfg() {
  return {
    email:         process.env.WB_EMAIL,
    client_id:     process.env.WB_CLIENT_ID,
    client_secret: process.env.WB_CLIENT_SECRET,
    gstin:         process.env.WB_GSTIN,
    username:      process.env.WB_USERNAME,
    password:      process.env.WB_PASSWORD,
    env:           process.env.WB_ENV || "sandbox",
    ip:            process.env.WB_IP_ADDRESS || "127.0.0.1",
  };
}

function httpsJson(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let raw = "";
      res.on("data", (c) => (raw += c));
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(raw); } catch {}
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on("error", reject);
    req.setTimeout(25000, () => req.destroy(new Error("WhiteBooks request timed out")));
    if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

/* ── Self-adapting API key check ────────────────────────────
   Accepts the key if EITHER its SHA-256 hash OR the raw key
   matches any string field of any doc in any of the usual
   key collections, and the doc isn't marked inactive/revoked.
   Result cached in memory for the warm instance. */
const keyOkCache = new Map(); // key -> boolean

async function verifyApiKey(req) {
  const key = req.get("X-Shipzy-API-Key");
  if (!key) return false;
  if (keyOkCache.has(key)) return keyOkCache.get(key);

  const hash = crypto.createHash("sha256").update(key).digest("hex");
  const candidates = [hash, hash.toUpperCase(), key];
  const collections = ["apiKeys", "api_keys", "apikeys", "keys", "apiClients"];

  let ok = false;
  for (const col of collections) {
    if (ok) break;
    try {
      const snap = await admin.firestore().collection(col).limit(100).get();
      for (const doc of snap.docs) {
        const d = doc.data() || {};
        const inactive = d.active === false || d.enabled === false || d.revoked === true || d.disabled === true;
        if (inactive) continue;
        const values = Object.values(d).filter(v => typeof v === "string");
        if (values.some(v => candidates.includes(v))) { ok = true; break; }
      }
    } catch (e) { /* collection may not exist — keep trying */ }
  }
  keyOkCache.set(key, ok);
  return ok;
}

let tokenCache = { token: null, expiresAt: 0 };

async function getWbToken(c) {
  const now = Date.now();
  if (tokenCache.token && now < tokenCache.expiresAt - 60_000) return tokenCache.token;

  const host = WB_HOSTS[c.env] || WB_HOSTS.sandbox;
  const q = `email=${encodeURIComponent(c.email || "")}` +
            `&username=${encodeURIComponent(c.username || "")}` +
            `&password=${encodeURIComponent(c.password || "")}`;
  const resp = await httpsJson({
    host,
    path: `${process.env.WB_PATH_PREFIX || ""}/ewaybillapi/v1.03/authenticate?${q}`,
    method: "GET",
    headers: {
      // belt & suspenders: send creds in headers too — gateway ignores extras
      "ip_address":    c.ip,
      "username":      c.username,
      "password":      c.password,
      "email":         c.email,
      "client_id":     c.client_id,
      "client_secret": c.client_secret,
      "gstin":         c.gstin,
      "Accept":        "application/json",
    },
  });

  const j = resp.json || {};
  // Success = status_cd "1" (or "Sucess" on some deployments). No token is
  // returned — the session is held server-side against gstin+client creds,
  // which is why data calls need no token header.
  const ok = j.status_cd === "1" || j.status_cd === 1 || j.status_cd === "Sucess";
  if (!ok) {
    const sent = `host=${host} email=${c.email} user=${c.username} gstin=${c.gstin} ip=${c.ip} env=${c.env}`;
    throw new Error(`WhiteBooks auth failed (HTTP ${resp.status}): ${String(resp.raw).slice(0, 200)} | sent: ${sent}`);
  }
  const token =
    j?.data?.authtoken || j?.data?.AuthToken || j?.data?.access_token ||
    j?.authtoken || "session";
  tokenCache = { token, expiresAt: now + 50 * 60_000 };
  return token;
}

/* Official NIC e-way bill error codes (full list from portal docs) */
const NIC_ERRORS = {
  "100": "Invalid Json",
  "101": "Invalid Username",
  "102": "Invalid Password",
  "103": "Invalid Client -Id",
  "104": "Invalid Client Secret",
  "105": "Invalid Token",
  "106": "Token Expired",
  "107": "Authentication failed. Pls. inform the helpdesk",
  "108": "Invalid login credentials.",
  "109": "Decryption of data failed",
  "110": "Invalid Client-ID/Client-Secret",
  "111": "GSTIN is not registerd to this GSP",
  "112": "Inactive Client",
  "113": "Inactive User",
  "114": "Technical Error, Pl. contact the helpdesk.",
  "115": "Request payload data cannot be empty",
  "116": "Auth token is not valid for this client",
  "117": "This option is not enabled in Eway Bill 2",
  "118": "Try after 5 minutes",
  "201": "Invalid Supply Type",
  "202": "Invalid Sub-supply Type",
  "203": "Sub-transaction type does not belongs to transaction type",
  "204": "Invalid Document type",
  "205": "Document type does not match with transaction & Sub trans type",
  "206": "Invaild Invoice Number",
  "207": "Invalid Invoice Date",
  "208": "Invalid Supplier GSTIN / Enrolled URP",
  "209": "Blank Supplier Address",
  "210": "Invalid or Blank Supplier PIN Code",
  "211": "Invalid or Blank Supplier state Code",
  "212": "Invalid Consignee GSTIN / Enrolled URP",
  "213": "Invalid Consignee Address",
  "214": "Invalid Consignee PIN Code",
  "215": "Invalid Consignee State Code",
  "216": "Invalid HSN Code",
  "217": "Invalid UQC Code",
  "218": "Invalid Tax Rate for Intra State Transaction",
  "219": "Invalid Tax Rate for Inter State Transaction",
  "220": "Invalid Trans mode",
  "221": "Invalid Approximate Distance",
  "222": "Invalid Transporter Id",
  "223": "Invalid Transaction Document Number",
  "224": "Invalid Transaction Date",
  "225": "Invalid Vehicle Number Format",
  "226": "Both Transaction and Vehicle Number Blank",
  "227": "User Gstin cannot be blank",
  "228": "User id cannot be blank",
  "229": "Supplier name is required",
  "230": "Supplier place is required",
  "231": "Consignee name is required",
  "232": "Consignee place is required",
  "233": "Eway bill does not contains any items",
  "234": "Total amount/Taxable amout is mandatory",
  "235": "Tax rates for Intra state transaction is blank",
  "236": "Tax rates for Inter state transaction is blank",
  "237": "Invalid client -Id/client-secret",
  "238": "Invalid auth token",
  "239": "Invalid action",
  "240": "Could not generate eway bill, pls contact helpdesk",
  "242": "Invalid State Code",
  "250": "Invalid Vehicle Release Date Format",
  "251": "CGST nad SGST TaxRate should be same",
  "252": "Invalid CGST Tax Rate",
  "253": "Invalid SGST Tax Rate",
  "254": "Invalid IGST Tax Rate",
  "255": "Invalid CESS Rate",
  "278": "User Gstin does not match with Transporter Id",
  "280": "Status is not ACTIVE",
  "281": "Eway Bill is already expired hence update transporter is not allowed.",
  "282": "At least 4 digit HSN code is mandatory for taxpayers with turnover less than 5Cr.",
  "283": "At least 6 digit HSN code is mandatory for taxpayers with turnover 5Cr. and above",
  "301": "Invalid eway bill number",
  "302": "Invalid transporter mode",
  "303": "Vehicle number is required",
  "304": "Invalid vehicle format",
  "305": "Place from is required",
  "306": "Invalid from state",
  "307": "Invalid reason",
  "308": "Invalid remarks",
  "309": "Could not update vehicle details, pl contact helpdesk",
  "311": "Validity period lapsed, you cannot update vehicle details",
  "312": "This eway bill is either not generated by you or cancelled",
  "315": "Validity period lapsed, you cannot cancel this eway bill",
  "316": "Eway bill is already verified, you cannot cancel it",
  "317": "Could not cancel eway bill, please contact helpdesk",
  "320": "Invalid state to",
  "321": "Invalid place to",
  "322": "Could not generate consolidated eway bill",
  "325": "Could not retrieve data",
  "326": "Could not retrieve GSTIN details for the given GSTIN number",
  "327": "Could not retrieve data from hsn",
  "328": "Could not retrieve transporter details from gstin",
  "329": "Could not retrieve States List",
  "330": "Could not retrieve UQC list",
  "331": "Could not retrieve Error code",
  "334": "Could not retrieve user details by userid ",
  "336": "Could not retrieve transporter data by gstin ",
  "337": "Could not retrieve HSN details for the given HSN number",
  "338": "You cannot update transporter details, as the current tranporter is already entered Part B details of the eway bill",
  "339": "You are not assigned to update the tranporter details of this eway bill",
  "341": "This e-way bill is generated by you and hence you cannot reject it",
  "342": "You cannot reject this e-way bill as you are not the other party to do so",
  "343": "This e-way bill is cancelled",
  "344": "Invalid eway bill number",
  "345": "Validity period lapsed, you cannot reject the e-way bill",
  "346": "You can reject the e-way bill only within 72 hours from generated timel",
  "347": "Validation of eway bill number failed, while rejecting ewaybill",
  "350": "Could not generate consolidated eway bill",
  "351": "Invalid state code",
  "352": "Invalid rfid date",
  "353": "Invalid location code",
  "354": "Invalid rfid number",
  "355": "Invalid Vehicle Number Format",
  "356": "Invalid wt on bridge",
  "357": "Could not retrieve eway bill details, pl. contact helpdesk",
  "358": "GSTIN passed in request header is not matching with the user gstin mentioned in payload JSON",
  "359": "User GSTIN should match to GSTIN(from) for outward transactions",
  "360": "User GSTIN should match to GSTIN(to) for inward transactions",
  "361": "Invalid Vehicle Type",
  "362": "Transporter document date cannot be earlier than the invoice date",
  "363": "E-way bill is not enabled for intra state movement for you state",
  "364": "Error in verifying eway bill",
  "365": "Error in verifying consolidated eway bill",
  "366": "You will not get the ewaybills generated today, howerver you cann access the ewaybills of yester days",
  "367": "Could not retrieve data for officer login",
  "368": "Could not update transporter",
  "369": "GSTIN/Transin passed in request header should match with the transported Id mentioned in payload JSON",
  "370": "GSTIN/Transin passed in request header should not be the same as supplier(fromGSTIN) or recepient(toGSTIN)",
  "371": "Invalid or Blank Supplier Ship-to State Code",
  "372": "Invalid or Blank Consignee Ship-to State Code",
  "373": "The Supplier ship-from state code should be Other Country for Sub Supply Type- Export",
  "374": "The Consignee pin code should be 999999 for Sub Supply Type- Export",
  "375": "The Supplier ship-to state code should be Other Country for Sub Supply Type- Import",
  "376": "The Supplier pin code should be 999999 for Sub Supply Type- Import",
  "377": "Sub Supply Type is mentioned as Others, the description for that is mandatory",
  "378": "The supplier or conginee belong to SEZ, Inter state tax rates are applicable here",
  "379": "Eway Bill can not be extended.. Already Cancelled",
  "380": "Eway Bill Can not be Extended. Not in Active State",
  "381": "There is No PART-B/Vehicle Entry.. So Please Update Vehicle Information..",
  "382": "You Cannot Extend as EWB can be Extended only 8 hour before or after w.r.t Validity of EWB..!!",
  "383": "Error While Extending..Please Contact Helpdesk. ",
  "384": "You are not current transporter or Generator of the ewayBill, with no transporter details.",
  "385": "For Rail/Ship/Air transDocNo and transDocDate is mandatory",
  "386": "Reason Code, Remarks is mandatory.",
  "387": "No Record Found for Entered consolidated eWay bill.",
  "388": "Exception in regenration of consolidated eWayBill!!Please Contact helpdesk",
  "389": "Remaining Distance Required",
  "390": "Remaining Distance Can not be greater than Actual Distance.",
  "391": "No eway bill of specified tripsheet, neither  ACTIVE nor not Valid.",
  "392": "Tripsheet is already cancelled, Hence Regeration is not possible",
  "393": "Invalid GSTIN",
  "394": "For other than Road Transport, TransDoc number is required",
  "395": "Eway Bill Number should be numeric only",
  "396": "Either Eway Bill Number Or Consolidated Eway Bill Number is required for Verification",
  "397": "Error in Multi Vehicle Movement Initiation",
  "398": "Eway Bill Item List is Empty",
  "399": "Unit Code is not matching with any of the Unit Code from ItemList",
  "400": "total quantity is exceeding from multi vehicle movement initiation quantity",
  "401": "Error in inserting multi vehicle details",
  "402": "total quantity can not be less than or equal to zero",
  "403": "Error in multi vehicle details",
  "405": "No record found for multi vehicle update with specified ewbNo groupNo and old vehicleNo/transDocNo with status as ACT",
  "406": "Group number cannot be empty or zero",
  "407": "Invalid old vehicle number format",
  "408": "Invalid new vehicle number format",
  "409": "Invalid old transDoc number",
  "410": "Invalid new transDoc number",
  "411": "Multi Vehicle Initiation data is not there for specified ewayBill and group No",
  "412": "Multi Vehicle movement is already Initiated,hence PART B updation not allowed",
  "413": "Unit Code is not matching with unit code of first initiaton",
  "415": "Error in fetching in verification data for officer",
  "416": "Date range is exceeding allowed date range ",
  "417": "No verification data found for officer ",
  "418": "No record found",
  "419": "Error in fetching search result for taxpayer/transporter",
  "420": "Minimum six character required for Tradename/legalname search",
  "421": "Invalid pincode",
  "422": "Invalid mobile number",
  "423": "Error in fetching ewaybill list by vehicle number",
  "424": "Invalid PAN number",
  "432": "invalid vehicle released value",
  "433": "invalid goods detained parameter value",
  "434": "invalid ewbNoAvailable parameter value",
  "435": "Part B is already updated,hence updation is not allowed",
  "436": "Invalid email id",
  "442": "Error in inserting verification details",
  "443": "invalid invoice available value",
  "444": "This eway bill cannot be cancelled as it is generated from Eway Bill 1",
  "445": "This eway bill cannot be cancelled as it is generated from Eway Bill 2",
  "446": "Transport details cannot be updated here as it is generated from Eway Bill 1",
  "447": "Transport details cannot be updated here as it is generated from Eway Bill 2",
  "448": "Part B cannot be updated as this Ewaybill Part A is generated in Eway Bill 1",
  "449": "Part B cannot be updated as this Ewaybill Part A is generated in Eway Bill 2",
  "450": "For outward-export ewaybill, To GSTIN has to be either URP or SEZ ",
  "451": "For inward-import ewaybill, From GSTIN has to be either URP or SEZ",
  "452": "Consolidate Ewaybill cannot be generated as this Ewaybill Part A is generated in Eway Bill 2",
  "600": "Invalid category",
  "601": "Invalid date format",
  "602": "Invalid File Number",
  "603": "For file details file number is required",
  "604": "E-way bill(s) are already generated for the same document number, you cannot generate again on same document number",
  "605": " If the goods are moving towards transporter location, the value of toTransporterLoc should be Y",
  "606": "Vehicle type is mandatory, if the goods are moving to transporter place",
  "607": "dispatch from gstin is mandatary ",
  "608": "ship to from gstin is mandatary",
  "609": " invalid ship to from gstin ",
  "610": "invalid dispatch from gstin ",
  "611": "invalid document type for the given supply type ",
  "612": "Invalid transaction type",
  "614": "Transaction type is mandatory",
  "617": "Bill-from and dispatch-from gstin should not be same for this transaction type",
  "618": "Bill-to and ship-to gstin should not be same for this transaction type",
  "619": "Transporter Id is mandatory for generation of Part A slip",
  "620": "Total invoice value cannot be less than the sum of total assessible value and tax values",
  "621": "trans mode is mandatory since vehicle number is present",
  "622": "trans mode is mandatory since trans doc number is present",
  "627": "Total value should not be negative",
  "628": "Total invoice value should not be negative",
  "629": "IGST value should not be negative",
  "630": "CGST value should not be negative",
  "631": "SGST value should not be negative",
  "632": "Cess value should not be negative",
  "633": "Cess non advol should not be negative",
  "634": "Vehicle type should not be ODC when transmode is other than road",
  "635": "You cannot update part B, as the current tranporter is already entered Part B details of the eway bill",
  "636": "You are not assigned to update part B",
  "637": "You cannot extend ewaybill, as the current tranporter is already entered Part B details of the ewaybill",
  "638": "Transport mode is mandatory as Vehicle Number/Transport Document Number is given",
  "640": "Tolal Invoice value is mandatory",
  "641": "For outward CKD/SKD/Lots supply type, Bill To state should be as Other Country, since the  Bill To GSTIN given is of SEZ unit",
  "642": "For inward CKD/SKD/Lots supply type, Bill From state should be as Other Country, since the  Bill From GSTIN given is of SEZ unit",
  "643": "For regular transaction, Bill from state code and Dispatch from state code should be same",
  "644": "For regular transaction, Bill to state code and Ship to state code should be same",
  "645": "You cannot do Multi Vehicle movement, as current transporeter already entered part B",
  "646": "You are not assigned to do multi vehicle movement",
  "647": "Could not insert RFID data, please contact to helpdesk",
  "648": "Multi Vehicle movement is already Initiated,hence generation of consolidated eway bill is not allowed",
  "649": "You cannot generate consolidated eway bill , as the current tranporter is already entered Part B details of the eway bill",
  "650": "You are not assigned to generate consolidated ewaybill",
  "651": "For Category PartA or PartB ewbDt is mandatory",
  "652": "For Category EWB03 procDt is mandatory",
  "653": "The Ewaybill is cancelled",
  "654": "This GSTIN has generated a common Enrolment Number. Hence you are not allowed to generate Eway bill",
  "655": "This GSTIN has generated a common Enrolment Number. Hence you cannot mention it as a transporter",
  "656": "This Eway Bill does not belongs to your state",
  "657": "Eway Bill Category wise details will be available after 4 days only",
  "658": "You are blocked for accesing this API as the allowed number of requests has been exceeded",
  "659": "Remarks is mandatory",
  "670": "Invalid Month Parameter",
  "671": "Invalid Year Parameter",
  "672": "User Id is mandatory",
  "673": "Error in getting officer dashboard",
  "675": "Error in getting EWB03 details by acknowledgement date range",
  "678": "Invalid Uniq No",
  "679": "Invalid EWB03 Ack No",
  "680": "Invalid Close Reason",
  "681": "Error in Closing EWB  Verification Data",
  "682": "No Record available to Close",
  "683": "Error in fetching WatchList Data",
  "700": "You are not assigned to extend e-waybill",
  "711": "Invalid value for isInTransit field",
  "712": "Transit Type is not required as the good are not in movement",
  "713": "Transit Address is not required as the good are not in movement",
  "714": "Document type - Tax Invoice is not allowed for composite tax payer",
  "715": "The Consignor GSTIN is blocked from e-waybill generation as Return is not filed for past 2 months",
  "716": "The Consignee GSTIN is blocked from e-waybill generation as Return is not filed for past 2 months",
  "717": "The Transporter GSTIN is blocked from e-waybill generation as Return is not filed for past 2 months",
  "718": "The User GSTIN is blocked from Transporter Updation as Return is not filed for past 2 months",
  "719": "The Transporter GSTIN is blocked from Transporter Updation as Return is not filed for past 2 months",
  "800": "Redis server Is not Working  try after some time",
  "801": "Transporter id is not required for ewaybill for gold",
  "802": "Transporter name is not required for ewaybill for gold",
  "803": "TransDocNo is not required for ewaybill for gold",
  "804": "TransDocDate is not required for ewaybill for gold",
  "805": "Vehicle No is not required for ewaybill for gold",
  "806": "Vehicle Type is not required for ewaybill for gold",
  "807": "Transmode is mandatory for ewaybill for gold",
  "808": "Inter-State ewaybill is not allowed for gold",
  "809": "Other items are not allowed with eway bill for gold",
  "810": "Transport can not be updated for EwayBill For Gold",
  "811": "Vehicle can not be updated for EwayBill For Gold",
  "812": "ConsolidatedEWB cannot be generated for EwayBill For Gold ",
  "813": "Transporter id is not required for ewaybill for gold",
  "814": "Transporter name is not required for ewaybill for gold",
  "815": "TransDocNo is not required for ewaybill for gold",
  "816": "TransDocDate is not required for ewaybill for gold",
  "817": "Vehicle No is not required for ewaybill for gold",
  "818": "Validity period lapsed.Cannot generate consolidated Eway Bill",
  "819": "Ewaybill cannot be generated for the document date which is prior to 01/07/2017",
  "820": "You cannot generate e-Waybill with document date earlier than 180 days",
  "821": "e-Waybill cannot be extended as the allowed limit is 360 days",
  "822": "Both supplier and recipient cannot be URP"
};

const NIC_HINTS = {
  "325": " — check the number; the portal only shows bills where Shipzy's GSTIN is supplier, recipient or transporter",
  "238": " — session issue, tap Fetch again",
  "106": " — session expired, tap Fetch again",
};

function nicMessage(codes) {
  const list = String(codes || "").split(",").map(s => s.trim()).filter(Boolean);
  const msgs = list.map(c =>
    NIC_ERRORS[c] ? `${NIC_ERRORS[c]}${NIC_HINTS[c] || ""} (code ${c})` : `Portal error code ${c}`);
  return msgs.join("; ") || null;
}

function normalizeEwb(d) {
  if (!d) return null;
  return {
    ewbNo:         d.ewbNo ?? d.ewayBillNo ?? null,
    ewbDate:       d.ewayBillDate ?? d.ewbDate ?? null,
    validUpto:     d.validUpto ?? null,
    status:        d.status ?? null,
    docNo:         d.docNo ?? null,
    docDate:       d.docDate ?? null,
    totalInvValue: Number(d.totInvValue ?? d.totalValue ?? 0) || 0,
    fromGstin:     d.fromGstin ?? null,
    fromTrdName:   d.fromTrdName ?? null,
    fromPlace:     d.fromPlace ?? null,
    fromPincode:   d.fromPincode ?? null,
    toGstin:       d.toGstin ?? null,
    toTrdName:     d.toTrdName ?? null,
    toPlace:       d.toPlace ?? null,
    toPincode:     d.toPincode ?? null,
    vehicleNo:     Array.isArray(d.VehiclListDetails) && d.VehiclListDetails.length
                     ? d.VehiclListDetails[d.VehiclListDetails.length - 1].vehicleNo
                     : (d.vehicleNo ?? null),
    transporterId:   d.transporterId ?? null,
    transporterName: d.transporterName ?? null,
    saidToContain: Array.isArray(d.itemList) && d.itemList.length
                     ? (d.itemList[0].productDesc || d.itemList[0].productName || null)
                     : null,
    itemCount:     Array.isArray(d.itemList) ? d.itemList.length : 0,
    raw:           d,  // full NIC payload (items, all Part-B rows) for PDF rendering
  };
}

exports.apiEwbDetails = functions
  .region("us-central1")
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");

    try {
      if (!(await verifyApiKey(req))) {
        return res.status(401).json({ ok: false, error: "Invalid or missing API key" });
      }

      const ewbNo = String(req.query.ewbNo || "").replace(/\D/g, "");
      if (ewbNo.length !== 12) {
        return res.status(400).json({ ok: false, error: "ewbNo must be a 12-digit e-way bill number" });
      }

      const c = cfg();
      if (!c.client_id || !c.client_secret || !c.email) {
        return res.status(500).json({ ok: false, error: "WhiteBooks credentials missing — check functions/.env" });
      }

      const token = await getWbToken(c);
      const host = WB_HOSTS[c.env] || WB_HOSTS.sandbox;

      const resp = await httpsJson({
        host,
        path: `${process.env.WB_PATH_PREFIX || ""}/ewaybillapi/v1.03/ewayapi/getewaybill?email=${encodeURIComponent(c.email)}&ewbNo=${ewbNo}`,
        method: "GET",
        headers: {
          "ip_address":    c.ip,
          "client_id":     c.client_id,
          "client_secret": c.client_secret,
          "gstin":         c.gstin,
          "Accept":        "application/json",
        },
      });

      const j = resp.json || {};
      const failed = resp.status !== 200 ||
        j.status_cd === "0" || j.status === "0" ||
        j.error || j.errorCodes || (j.data && j.data.errorCodes);
      if (failed) {
        if (resp.status === 401) tokenCache = { token: null, expiresAt: 0 };
        const codes = j?.errorCodes || j?.data?.errorCodes;
        const msg = nicMessage(codes) || j?.error?.message ||
                    j?.status_desc || `EWB lookup failed (HTTP ${resp.status})`;
        return res.status(502).json({ ok: false, error: String(msg).slice(0, 300) });
      }

      const payload = j.data ?? j;
      return res.json({ ok: true, data: normalizeEwb(payload) });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e.message || "Internal error" });
    }
  });


/* ── apiEwbActions: create / update Part-B / extend validity ──
   POST body: { action: "create"|"partb"|"extend", payload: {...} }
   Payload shapes follow the NIC spec exactly (see Postman collection):
     create → genewaybill, partb → vehewb, extend → extendvalidity */

const ACTION_PATHS = {
  create: "/ewaybillapi/v1.03/ewayapi/genewaybill",
  partb:  "/ewaybillapi/v1.03/ewayapi/vehewb",
  extend: "/ewaybillapi/v1.03/ewayapi/extendvalidity",
};

exports.apiEwbActions = functions
  .region("us-central1")
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");
    if (req.method !== "POST") return res.status(405).json({ ok: false, error: "POST only" });

    try {
      if (!(await verifyApiKey(req))) {
        return res.status(401).json({ ok: false, error: "Invalid or missing API key" });
      }

      const { action, payload } = req.body || {};
      const path = ACTION_PATHS[action];
      if (!path)   return res.status(400).json({ ok: false, error: "action must be create | partb | extend" });
      if (!payload || typeof payload !== "object")
        return res.status(400).json({ ok: false, error: "payload object required" });

      const c = cfg();
      if (!c.client_id || !c.client_secret || !c.email) {
        return res.status(500).json({ ok: false, error: "WhiteBooks credentials missing — check functions/.env" });
      }

      await getWbToken(c); // establishes the server-side session
      const host = WB_HOSTS[c.env] || WB_HOSTS.sandbox;

      const resp = await httpsJson({
        host,
        path: `${process.env.WB_PATH_PREFIX || ""}${path}?email=${encodeURIComponent(c.email)}`,
        method: "POST",
        headers: {
          "ip_address":    c.ip,
          "client_id":     c.client_id,
          "client_secret": c.client_secret,
          "gstin":         c.gstin,
          "Content-Type":  "application/json",
          "Accept":        "application/json",
        },
      }, payload);

      const j = resp.json || {};
      const codes = j?.errorCodes || j?.data?.errorCodes;
      const failed = resp.status !== 200 || j.status_cd === "0" || j.status === "0" || codes || j.error;
      if (failed) {
        const msg = nicMessage(codes) || j?.error?.message ||
                    j?.status_desc || `Portal call failed (HTTP ${resp.status})`;
        return res.status(502).json({ ok: false, error: String(msg).slice(0, 400) });
      }

      const d = j.data ?? j;
      return res.json({
        ok: true,
        action,
        data: {
          ewbNo:      d.ewayBillNo ?? d.ewbNo ?? null,
          ewbDate:    d.ewayBillDate ?? d.ewbDt ?? null,
          validUpto:  d.validUpto ?? null,
          vehUpdDate: d.vehUpdDate ?? null,
          alert:      d.alert ?? null,
          raw:        d,
        },
      });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e.message || "Internal error" });
    }
  });


/* ── apiGstinDetails: verify a GSTIN via the e-way bill portal ──
   GET ?gstin=15CHARGSTIN → registered names, address, status. */
exports.apiGstinDetails = functions
  .region("us-central1")
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");

    try {
      if (!(await verifyApiKey(req))) {
        return res.status(401).json({ ok: false, error: "Invalid or missing API key" });
      }

      const gstin = String(req.query.gstin || "").trim().toUpperCase();
      if (!/^[0-9]{2}[A-Z0-9]{13}$/.test(gstin)) {
        return res.status(400).json({ ok: false, error: "gstin must be a valid 15-character GSTIN" });
      }

      const c = cfg();
      if (!c.client_id || !c.client_secret || !c.email) {
        return res.status(500).json({ ok: false, error: "WhiteBooks credentials missing — check functions/.env" });
      }

      await getWbToken(c);
      const host = WB_HOSTS[c.env] || WB_HOSTS.sandbox;

      const resp = await httpsJson({
        host,
        path: `${process.env.WB_PATH_PREFIX || ""}/ewaybillapi/v1.03/ewayapi/getgstindetails?email=${encodeURIComponent(c.email)}&GSTIN=${gstin}`,
        method: "GET",
        headers: {
          "ip_address":    c.ip,
          "client_id":     c.client_id,
          "client_secret": c.client_secret,
          "gstin":         c.gstin,
          "Accept":        "application/json",
        },
      });

      const j = resp.json || {};
      const codes = j?.errorCodes || j?.data?.errorCodes;
      const failed = resp.status !== 200 || j.status_cd === "0" || j.status === "0" || codes || j.error;
      if (failed) {
        const msg = nicMessage(codes) || j?.error?.message ||
                    j?.status_desc || `GSTIN lookup failed (HTTP ${resp.status})`;
        return res.status(502).json({ ok: false, error: String(msg).slice(0, 300) });
      }

      const d = j.data ?? j;
      return res.json({
        ok: true,
        data: {
          gstin:      d.gstin ?? gstin,
          legalName:  d.legalName ?? d.lgnm ?? null,
          tradeName:  d.tradeNam ?? d.tradeName ?? d.tradenam ?? null,
          address1:   d.address1 ?? d.addr1 ?? null,
          address2:   d.address2 ?? d.addr2 ?? null,
          place:      d.place ?? d.loc ?? null,
          stateCode:  d.stateCode ?? null,
          pinCode:    d.pinCode ?? d.pincode ?? null,
          taxpayerType: d.txpType ?? null,   // REG / COM / CAS / UNR / TDS...
          status:     d.status ?? null,      // ACT = active, CNL = cancelled
          blocked:    d.blkStatus ?? null,   // B = blocked from EWB generation
          regDate:    d.dtReg ?? null,
          raw:        d,
        },
      });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e.message || "Internal error" });
    }
  });


/* ── apiShareLr: share LR by Email (SMTP) + WhatsApp (Cloud API) ──
   POST { subject, text, detailsHtml, lrHtml, filename,
          to[], cc[], waNumbers[], waText }
   Env (.env):
     SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
     WA_PHONE_ID, WA_TOKEN   (WhatsApp Business Cloud API)          */

function sendSmtpMail({ to, cc, subject, text, html, attachment }) {
  return new Promise((resolve) => {
    let nodemailer;
    try { nodemailer = require("nodemailer"); }
    catch { return resolve({ ok: false, error: "nodemailer not installed — run npm install in functions/" }); }
    const ic = arguments[0].icfg || {};
    const host = ic.smtpHost || process.env.SMTP_HOST, user = ic.smtpUser || process.env.SMTP_USER, pass = ic.smtpPass || process.env.SMTP_PASS;
    if (!host || !user || !pass) return resolve({ ok: false, error: "SMTP not configured — set it in Settings → Integrations" });
    const port = Number(ic.smtpPort || process.env.SMTP_PORT || 587);
    const transporter = nodemailer.createTransport({
      host, port, secure: port === 465,
      auth: { user, pass },
    });
    transporter.sendMail({
      from: ic.mailFrom || process.env.MAIL_FROM || user,
      to: to.join(", "),
      cc: cc && cc.length ? cc.join(", ") : undefined,
      subject, text, html,
      attachments: attachment ? [{ filename: attachment.filename, content: attachment.content, contentType: "text/html" }] : [],
    }, (err) => {
      if (err) resolve({ ok: false, error: String(err.message || err).slice(0, 200) });
      else resolve({ ok: true });
    });
  });
}

function waSendText(phoneId, token, toNumber, body) {
  return new Promise((resolve) => {
    const payload = JSON.stringify({
      messaging_product: "whatsapp",
      to: toNumber,
      type: "text",
      text: { preview_url: false, body },
    });
    const req = https.request({
      host: "graph.facebook.com",
      path: `/v20.0/${phoneId}/messages`,
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    }, (res) => {
      let raw = "";
      res.on("data", c => raw += c);
      res.on("end", () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve({ ok: true });
        else {
          let msg = raw.slice(0, 200);
          try { msg = JSON.parse(raw).error?.message || msg; } catch {}
          resolve({ ok: false, error: msg });
        }
      });
    });
    req.on("error", (e) => resolve({ ok: false, error: e.message }));
    req.setTimeout(15000, () => req.destroy(new Error("timeout")));
    req.write(payload);
    req.end();
  });
}

exports.apiShareLr = functions
  .region("us-central1")
  .runWith({ timeoutSeconds: 120, memory: "256MB" })
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");
    if (req.method !== "POST") return res.status(405).json({ ok: false, error: "POST only" });

    try {
      if (!(await verifyApiKey(req))) {
        return res.status(401).json({ ok: false, error: "Invalid or missing API key" });
      }
      const b = req.body || {};
      const to = Array.isArray(b.to) ? b.to.filter(Boolean) : [];
      const cc = Array.isArray(b.cc) ? b.cc.filter(Boolean) : [];
      const waNumbers = (Array.isArray(b.waNumbers) ? b.waNumbers : [])
        .map(n => String(n).replace(/\D/g, ""))
        .map(n => n.length === 10 ? "91" + n : n)
        .filter(n => n.length >= 11);

      const icfg = await getIntegrations();
      const out = { emailOk: null, emailError: null, waSent: 0, waErrors: [] };

      if (to.length > 0) {
        const mail = await sendSmtpMail({
          icfg,
          to, cc,
          subject: String(b.subject || "LR — Shipzy Logistics").slice(0, 200),
          text: String(b.text || ""),
          html: String(b.detailsHtml || ""),
          attachment: b.lrHtml ? { filename: String(b.filename || "LR.html"), content: String(b.lrHtml) } : null,
        });
        out.emailOk = mail.ok;
        if (!mail.ok) out.emailError = mail.error;
      }

      if (waNumbers.length > 0) {
        const phoneId = icfg.waPhoneId || process.env.WA_PHONE_ID, token = icfg.waToken || process.env.WA_TOKEN;
        if (!phoneId || !token) {
          out.waErrors.push("WhatsApp not configured — set it in Settings → Integrations");
        } else {
          for (const num of waNumbers) {
            const r = await waSendText(phoneId, token, num, String(b.waText || b.text || ""));
            if (r.ok) out.waSent++;
            else out.waErrors.push(`${num}: ${r.error}`.slice(0, 120));
          }
        }
      }

      return res.json({ ok: true, data: out });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e.message || "Internal error" });
    }
  });


/* ── Integrations config: stored in THIS project's Firestore ──
   (collection "integrations", doc "config") so app users can never
   read secrets from the shared workspace state. Env vars remain a
   fallback. Cached per warm instance for 5 minutes. ── */
let _icfgCache = { at: 0, val: null };
async function getIntegrations() {
  const now = Date.now();
  if (_icfgCache.val && now - _icfgCache.at < 5 * 60_000) return _icfgCache.val;
  let val = {};
  try {
    const snap = await admin.firestore().collection("integrations").doc("config").get();
    if (snap.exists) val = snap.data() || {};
  } catch {}
  _icfgCache = { at: now, val };
  return val;
}

const _mask = (v) => v ? ("••••" + String(v).slice(-4)) : "";

exports.apiIntegrations = functions
  .region("us-central1")
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");
    try {
      if (!(await verifyApiKey(req))) return res.status(401).json({ ok: false, error: "Invalid or missing API key" });

      if (req.method === "GET") {
        const c = await getIntegrations();
        return res.json({ ok: true, data: {
          smtpHost: c.smtpHost || "", smtpPort: c.smtpPort || "",
          smtpUser: c.smtpUser || "", smtpPass: _mask(c.smtpPass),
          mailFrom: c.mailFrom || "",
          waPhoneId: _mask(c.waPhoneId), waToken: _mask(c.waToken),
          imapUser: c.imapUser || "", imapPass: _mask(c.imapPass),
        }});
      }

      const b = req.body || {};
      if (b.action === "save") {
        const allowed = ["smtpHost","smtpPort","smtpUser","smtpPass","mailFrom","waPhoneId","waToken","imapUser","imapPass"];
        const patch = {};
        allowed.forEach(k => {
          if (b.config && typeof b.config[k] === "string" && b.config[k].trim() !== "") {
            let v = b.config[k].trim();
            // Google app passwords are shown as "abcd efgh ijkl mnop" — the
            // real password has no spaces. Strip them for password fields.
            if (k === "smtpPass" || k === "imapPass") v = v.replace(/\s+/g, "");
            patch[k] = v;
          }
        });
        if (!Object.keys(patch).length) return res.status(400).json({ ok: false, error: "No fields to save" });
        await admin.firestore().collection("integrations").doc("config").set(patch, { merge: true });
        _icfgCache = { at: 0, val: null };
        return res.json({ ok: true, data: { saved: Object.keys(patch) } });
      }

      if (b.action === "test-email") {
        const icfg = await getIntegrations();
        const r = await sendSmtpMail({ icfg, to: [String(b.to || "")], cc: [],
          subject: "ShipzyCart test email ✅", text: "Email sending is configured correctly.",
          html: "<p>Email sending is configured correctly. — ShipzyCart</p>", attachment: null });
        return res.json({ ok: true, data: r });
      }

      if (b.action === "test-wa") {
        const icfg = await getIntegrations();
        const phoneId = icfg.waPhoneId || process.env.WA_PHONE_ID, token = icfg.waToken || process.env.WA_TOKEN;
        if (!phoneId || !token) return res.json({ ok: true, data: { ok: false, error: "WhatsApp not configured yet" } });
        let num = String(b.to || "").replace(/\D/g, "");
        if (num.length === 10) num = "91" + num;
        const r = await waSendText(phoneId, token, num, "ShipzyCart test message ✅ — WhatsApp sending is configured correctly.");
        return res.json({ ok: true, data: r });
      }

      return res.status(400).json({ ok: false, error: "Unknown action" });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e.message || "Internal error" });
    }
  });

/* ── Mail inbox (IMAP) — list + read, for the ftl-ops mailbox ── */
async function imapConnect() {
  const c = await getIntegrations();
  const user = c.imapUser || c.smtpUser || process.env.SMTP_USER;
  const pass = c.imapPass || c.smtpPass || process.env.SMTP_PASS;
  if (!user || !pass) throw new Error("Inbox not configured — set the mailbox in Settings → Integrations");
  const { ImapFlow } = require("imapflow");
  const client = new ImapFlow({
    host: "imap.gmail.com", port: 993, secure: true,
    auth: { user, pass },
    logger: false,
  });
  await client.connect();
  return client;
}

exports.apiInboxList = functions
  .region("us-central1")
  .runWith({ timeoutSeconds: 60, memory: "256MB" })
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");
    let client;
    try {
      if (!(await verifyApiKey(req))) return res.status(401).json({ ok: false, error: "Invalid or missing API key" });
      const limit = Math.min(Number(req.query.limit || 50), 100);
      client = await imapConnect();
      const lock = await client.getMailboxLock("INBOX");
      const messages = [];
      try {
        const total = client.mailbox.exists;
        if (total > 0) {
          const start = Math.max(1, total - limit + 1);
          for await (const m of client.fetch(`${start}:${total}`, { uid: true, envelope: true, flags: true })) {
            const env = m.envelope || {};
            const fromAddr = (env.from && env.from[0]) || {};
            messages.push({
              uid: m.uid,
              from: fromAddr.name ? `${fromAddr.name} <${fromAddr.address}>` : (fromAddr.address || ""),
              subject: env.subject || "",
              date: env.date ? new Date(env.date).toISOString() : "",
              seen: m.flags ? m.flags.has("\\Seen") : false,
            });
          }
        }
      } finally { lock.release(); }
      await client.logout();
      messages.reverse(); // newest first
      return res.json({ ok: true, data: { messages } });
    } catch (e) {
      try { client && client.close(); } catch {}
      return res.status(500).json({ ok: false, error: e.message || "Inbox error" });
    }
  });

exports.apiInboxGet = functions
  .region("us-central1")
  .runWith({ timeoutSeconds: 60, memory: "512MB" })
  .https.onRequest(async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, X-Shipzy-API-Key");
    if (req.method === "OPTIONS") return res.status(204).send("");
    let client;
    try {
      if (!(await verifyApiKey(req))) return res.status(401).json({ ok: false, error: "Invalid or missing API key" });
      const uid = Number(req.query.uid || 0);
      if (!uid) return res.status(400).json({ ok: false, error: "uid required" });
      client = await imapConnect();
      const lock = await client.getMailboxLock("INBOX");
      let parsed = null;
      try {
        const msg = await client.fetchOne(String(uid), { uid: true, source: true }, { uid: true });
        if (!msg || !msg.source) throw new Error("Message not found");
        const { simpleParser } = require("mailparser");
        parsed = await simpleParser(msg.source);
      } finally { lock.release(); }
      await client.logout();
      const addr = (a) => a && a.text ? a.text : "";
      return res.json({ ok: true, data: {
        uid,
        subject: parsed.subject || "",
        from: addr(parsed.from), to: addr(parsed.to), cc: addr(parsed.cc),
        date: parsed.date ? new Date(parsed.date).toISOString() : "",
        html: parsed.html || null,
        text: parsed.text || "",
      }});
    } catch (e) {
      try { client && client.close(); } catch {}
      return res.status(500).json({ ok: false, error: e.message || "Inbox error" });
    }
  });
