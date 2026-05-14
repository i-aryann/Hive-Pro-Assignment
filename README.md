# TawasolPay AI Cyber Risk Assistant

This repository contains a working FastAPI + React dashboard that prioritizes cyber risks. It goes beyond simple CVSS scoring by factoring in asset exposure, business criticality, active threat intelligence campaigns, and missing compensating controls. It also maps these risks to remediation guidance retrieved directly from the official NIST SP 800-53 catalog.

## How to run it locally

### Backend Setup
The backend is built with FastAPI and requires MongoDB to run.

1. Ensure you have a running MongoDB instance (either locally or MongoDB Atlas).
2. Open a terminal and navigate to the backend folder:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the `backend` folder (or copy `.env.example`) with the following:
   ```
   MONGO_URL=mongodb://localhost:27017 # Or your Atlas connection string
   DB_NAME=my_db
   CORS_ORIGINS=http://localhost:3000
   ```
4. Start the server:
   ```bash
   uvicorn server:app --host 0.0.0.0 --port 8001
   ```

### Frontend Setup
The frontend is a React application using TailwindCSS.

1. Open a new terminal and navigate to the frontend folder:
   ```bash
   cd frontend
   yarn install
   ```
2. Start the development server:
   ```bash
   yarn start
   ```
3. The dashboard will automatically open at `http://localhost:3000`. Use the UI to upload the data pack CSVs, sync the NIST and CISA KEV data, and view the ranked risks.

---

## Supporting Question 1: The data split

**What data did you embed and why?**
I embedded the text of the NIST SP 800-53 controls (the control descriptions, discussion sections, and related guidelines). I did this because remediation guidance is inherently long-form prose; when a user asks "how do I fix this?", semantic vector search is the best way to find relevant, context-aware policy recommendations rather than relying on strict keyword matches.

**What data did you query as structured records and why?**
I kept the assets, vulnerabilities, threat intelligence, and business services strictly as structured records in MongoDB. I did this because risk ranking requires deterministic, mathematical evaluation—exact joins between asset IDs, boolean checks for internet exposure, and numeric weighting of CVSS scores. If I put facts like "is this asset internet exposed?" into a vector database, the risk scoring would become fuzzy, unpredictable, and impossible to audit. 

## Supporting Question 2: Where it goes wrong

Here are three specific ways the system can produce an incorrect or misleading output:

1. **Asset mapping failures blinding the system:** If a vulnerability in the `vulnerabilities.csv` file has an `asset_id` that doesn't exactly match any asset in `assets.csv`, the system silently skips scoring it, completely missing that risk. To catch this, I would add a validation step during data upload that explicitly tallies and warns the user about "orphan vulnerabilities" so they know their asset inventory is incomplete.
2. **Over-inflating scores via blind threat matches:** If the threat intel feed flags a specific CVE as being actively exploited, the system bumps its score. However, if that CVE is a Windows Server bug, but our specific asset is running a Linux environment, the system will incorrectly inflate the score because it only matched on the CVE string. Catching this requires parsing the exact OS/platform strings from the asset data to ensure the threat actually applies to the specific environment.
3. **Outdated CISA KEV catalog syncs:** If a CVE was added to the CISA catalog an hour ago, but the system hasn't had its `/api/cisa-kev/sync` endpoint triggered recently, the vulnerability won't be flagged as actively exploited, severely undervaluing the risk. To catch this, I display the "last synced" timestamp directly in the UI so the user knows exactly how fresh the data is, though this could be improved by running a background cron job to auto-sync it daily.

## Supporting Question 3: One thing I would change

If I had another day, the single most important thing I would improve is the **data ingestion and conflict resolution pipeline**. Right now, the system trusts the uploaded CSVs blindly; if an asset has missing owner information, or if a vulnerability has a malformed CVSS score, it just does its best to ingest it without complaining. In a real enterprise environment, data is never perfectly clean. I would build a robust validation layer (using Pydantic) that catches malformed rows, rejects impossible values, and generates a "Data Quality Report" immediately after upload. Security teams need to know exactly what data they are missing or what data is broken *before* they can trust the risk decisions the system is making.