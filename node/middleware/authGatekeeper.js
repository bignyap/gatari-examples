import jwt from 'jsonwebtoken';
import axios from 'axios';

function authGatekeeper(gatekeeperUrl) {
  return async function (req, res, next) {
    const tokenData = extractToken(req);
    if (tokenData.error) {
      return res.status(401).json({ detail: tokenData.error });
    }

    req.realm = tokenData.realm;
    req.token_payload = tokenData.payload;

    try {
      const validation = await validateWithGatekeeper(req, gatekeeperUrl);
      req.validation = validation;
    } catch (err) {
      return res.status(err.status || 500).json({ detail: err.message });
    }

    next();

    res.on('finish', () => {
      recordUsage(req, gatekeeperUrl).catch(err =>
        console.error("Usage recorder error:", err.message)
      );
    });
  };
}

function extractToken(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { error: "Missing or invalid auth token" };
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.decode(token);
    const realm = payload?.realm;

    if (!realm) throw new Error("Missing 'realm'");
    return { realm, payload };
  } catch (e) {
    return { error: `Invalid token: ${e.message}` };
  }
}

async function validateWithGatekeeper(req, gatekeeperUrl) {
  const payload = {
    organization_name: req.realm,
    method: req.method,
    path: req.path,
  };

  try {
    const response = await axios.post(`${gatekeeperUrl}/validate`, payload);
    return response.data;
  } catch (err) {
    if (err.response && err.response.status === 403) {
      throw { message: "Unauthorized by gatekeeper", status: 403 };
    }
    throw { message: `Gatekeeper validation failed: ${err.message}`, status: 500 };
  }
}

async function recordUsage(req, gatekeeperUrl) {
  const usagePayload = {
    organization_name: req.realm,
    method: req.method,
    path: req.path,
  };

  try {
    await axios.post(`${gatekeeperUrl}/recordUsage`, usagePayload);
  } catch (err) {
    console.warn("Usage recording failed:", err.message);
  }
}

export default authGatekeeper;