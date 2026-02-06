import express from "express";
import axios from "axios";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Read from Render Environment Variables
const CLIENT_ID = process.env.SPLITWISE_CLIENT_ID;
const CLIENT_SECRET = process.env.SPLITWISE_CLIENT_SECRET;
const REDIRECT_URI = process.env.SPLITWISE_REDIRECT_URI;
const STATE_SECRET = process.env.SPLITWISE_STATE_SECRET;


// Temporary in-memory token storage
let accessToken = null;
let refreshToken = null;


function signState(payload) {
    const json = JSON.stringify(payload);
    const b64 = Buffer.from(json).toString("base64url");
    const sig = crypto
        .createHmac("sha256", STATE_SECRET)
        .update(b64)
        .digest("base64url");
    return `${b64}.${sig}`;
}

function verifyState(state) {
    if (!state || !STATE_SECRET) return null;

    const [b64, sig] = state.split(".");
    if (!b64 || !sig) return null;

    const expected = crypto
        .createHmac("sha256", STATE_SECRET)
        .update(b64)
        .digest("base64url");

    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
        return null;
    }

    const json = Buffer.from(b64, "base64url").toString("utf8");
    const payload = JSON.parse(json);

    // 10 min expiry
    const maxAgeMs = 10 * 60 * 1000;
    if (Date.now() - payload.ts > maxAgeMs) return null;

    return payload;
}


app.get("/auth/start", (req, res) => {
    if (!STATE_SECRET) {
        return res.status(500).send("Missing SPLITWISE_STATE_SECRET");
    }

    const state = signState({ ts: Date.now() });

    const params = new URLSearchParams({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        state
    });

    return res.redirect(`https://secure.splitwise.com/oauth/authorize?${params.toString()}`);
});

// 1️⃣ OAuth Redirect Handler
app.get("/splitwise/callback", async (req, res) => {
    const code = req.query.code;
    const state = req.query.state;

    console.log("Callback hit with code:", code);

    const verified = verifyState(state);
    if (!verified) {
        return res.status(400).send("Invalid state");
    }

    console.log("CLIENT_ID:", CLIENT_ID);
    console.log("CLIENT_SECRET present:", CLIENT_SECRET ? "YES" : "NO");
    console.log("REDIRECT_URI:", REDIRECT_URI);

    if (!code) {
        return res.status(400).send("No code received.");
    }

    try {
        const tokenResponse = await axios.post(
            "https://secure.splitwise.com/oauth/token",
            new URLSearchParams({
                grant_type: "authorization_code",
                code,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: REDIRECT_URI
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );

        accessToken = tokenResponse.data.access_token;
        refreshToken = tokenResponse.data.refresh_token;

        console.log("✔ Splitwise tokens saved!", tokenResponse.data);

        return res.send("✔ Successfully connected to Splitwise! You may close this window.");
    } catch (error) {
        console.error("OAuth Error status:", error.response?.status);
        console.error("OAuth Error data:", error.response?.data);
        return res.status(500).send("OAuth error.");
    }
});

// 4️⃣ Get current Splitwise user
app.get("/api/me", async (req, res) => {
    if (!accessToken)
        return res.status(401).json({ error: "Not authenticated" });

    try {
        const response = await axios.get(
            "https://secure.splitwise.com/api/v3.0/get_current_user",
            {
                headers: { Authorization: `Bearer ${accessToken}` }
            }
        );

        console.log("Fetched current user:", response.data);
        return res.json(response.data);
    } catch (err) {
        console.error("Get user error:", err.response?.data || err);
        res.status(500).json({ error: "Failed to fetch user" });
    }
});

// 3️⃣ API endpoint to get expenses (with date filter)
app.get("/api/expenses", async (req, res) => {
    if (!accessToken) return res.status(401).json({ error: "Not authenticated" });

    const since = req.query.since;

    try {
        const response = await axios.get(
            `https://secure.splitwise.com/api/v3.0/get_expenses?dated_after=${since}`,
            {
                headers: { Authorization: `Bearer ${accessToken}` }
            }
        );

        console.log("Expenses returned:", response.data.expenses.length);
        console.log(JSON.stringify(response.data.expenses, null, 2));

        return res.json(response.data);
    } catch (err) {
        console.error(err.response?.data || err.message);
        return res.status(500).send("Failed to fetch expenses");
    }
});


// Root route to prevent 404 on backend root
app.get("/", (req, res) => {
    res.send("Splitwise Backend is running!");
});

// Health check route for uptime monitors
app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});




// 4️⃣ Start server on Render's port
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Backend running on port ${PORT}`);
});
