/* Exports every workspaces/{ws}/state + presence doc to ./backup-out as
   pretty JSON. Stringified "value" fields are parsed so successive git
   commits diff cleanly (git keeps full history = point-in-time restore). */
import admin from "firebase-admin";
import fs from "fs";
import path from "path";

const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({ credential: admin.credential.cert(sa) });
const db = admin.firestore();

const OUT = "backup-out";
fs.rmSync(OUT, { recursive: true, force: true });

const writeDoc = (file, data) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
};

// listDocuments() (not .get()) — parents of subcollections are "virtual"
// docs in Firestore when never explicitly created, and .get() skips them.
const wsRefs = await db.collection("workspaces").listDocuments();
let docs = 0;
for (const ws of wsRefs) {
  for (const sub of ["state", "presence"]) {
    const snap = await ws.collection(sub).get();
    for (const d of snap.docs) {
      const data = d.data();
      if (typeof data.value === "string") {
        try { data.value = JSON.parse(data.value); } catch { /* keep raw */ }
      }
      writeDoc(path.join(OUT, ws.id, sub, `${d.id}.json`), data);
      docs++;
    }
  }
}
writeDoc(path.join(OUT, "_meta.json"), {
  backedUpAt: new Date().toISOString(),
  workspaces: wsRefs.length,
  documents: docs,
});
console.log(`Backed up ${docs} docs from ${wsRefs.length} workspace(s)`);
