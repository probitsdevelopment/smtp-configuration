import { useEffect, useState } from "react";
import googleLogo from "../assets/google.svg";
import microsoftLogo from "../assets/microsoft.svg";
import "../styles/email.css";

function Email() {
  const apiBaseUrl = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";
  const [provider, setProvider] = useState(null);
  const [connected, setConnected] = useState(false);
  const [sending, setSending] = useState(false);
  const [statusChecked, setStatusChecked] = useState(false);
  const [lastRefreshedAt, setLastRefreshedAt] = useState(null);
  const [lastLoginAt, setLastLoginAt] = useState(null);

  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const p = params.get("provider");

    if (p) {
      setProvider(p);
      setConnected(true);
      window.history.replaceState({}, "", "/email");
    }

    const fetchStatus = async () => {
      try {
        const res = await fetch(`${apiBaseUrl}/status`);
        if (!res.ok) {
          return;
        }
        const data = await res.json();
        if (data.connected && data.providers && data.providers.length > 0) {
          const primary = data.providers[0].provider;
          const updatedAt = data.providers[0].updated_at;
          const loginAt = data.providers[0].last_login_at;
          const refreshAt = data.providers[0].last_refresh_at;
          setProvider(primary);
          setConnected(true);
          const inferredLoginAt = loginAt || (!refreshAt && updatedAt ? updatedAt : null);
          setLastLoginAt(inferredLoginAt);
          setLastRefreshedAt(refreshAt || updatedAt || null);
        }
      } catch (err) {
        console.error("Status check failed", err);
      } finally {
        setStatusChecked(true);
      }
    };

    fetchStatus();
  }, [apiBaseUrl]);

  const formatTimestamp = (unixSeconds) => {
    if (!unixSeconds) {
      return "unknown";
    }
    return new Date(unixSeconds * 1000).toLocaleString();
  };

  const connectGoogle = () => {
    window.location.href = `${apiBaseUrl}/auth/google`;
  };

  const connectMicrosoft = () => {
    window.location.href = `${apiBaseUrl}/auth/microsoft`;
  };

  const logout = async () => {
    await fetch(`${apiBaseUrl}/logout`, {
      method: "POST",
    });

    setConnected(false);
    setProvider(null);
    setTo("");
    setSubject("");
    setMessage("");
  };

  const sendEmail = async () => {
  if (!provider) {
    alert("No provider connected");
    return;
  }

  setSending(true);

  const endpoint =
    provider === "google"
      ? `${apiBaseUrl}/send/google`
      : `${apiBaseUrl}/send/microsoft`;

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, subject, message }),
    });

    if (!res.ok) {
      const errorText = await res.text();
      console.error("Send error:", errorText);
      throw new Error(errorText);
    }

    alert("✅ Email sent successfully!");
    setTo("");
    setSubject("");
    setMessage("");
  } catch (err) {
    alert("❌ Failed to send email");
    console.error(err);
  } finally {
    setSending(false);
  }
};


  return (
    <div className="page">
      <div className="card">
        <h1>Email Sender</h1>
        <p className="subtitle">
          Send emails securely using your own Gmail or Outlook account
        </p>

        <div className="status-indicator">
          {!statusChecked && "Checking connection..."}
          {statusChecked && !connected && "Not connected"}
          {statusChecked && connected && (
            <span>
              Connected to {provider} | Last login: {formatTimestamp(lastLoginAt)} | Last refresh: {formatTimestamp(lastRefreshedAt)}
            </span>
          )}
        </div>

        {!connected && (
          <div className="connect-section">
            <button className="oauth google" onClick={connectGoogle}>
              <img
                src={googleLogo}
                alt="Gmail"
              />
              Connect Gmail
            </button>

            <button className="oauth microsoft" onClick={connectMicrosoft}>
              <img
                src={microsoftLogo}
                alt="Outlook"
              />
              Connect Outlook
            </button>
          </div>
        )}

        {connected && (
          <>
            <div className="status-bar">
              <div className="status">
                ✅ Connected via <strong>{provider}</strong>
              </div>

              <button className="logout" onClick={logout}>
                Logout
              </button>
            </div>

            <div className="form">
              <label>To</label>
              <input
                type="email"
                placeholder="recipient@example.com"
                value={to}
                onChange={(e) => setTo(e.target.value)}
              />

              <label>Subject</label>
              <input
                type="text"
                placeholder="Subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />

              <label>Message</label>
              <textarea
                rows="6"
                placeholder="Write your message..."
                value={message}
                onChange={(e) => setMessage(e.target.value)}
              />

              <button
                className="send"
                onClick={sendEmail}
                disabled={sending}
              >
                {sending ? "Sending..." : "Send Email"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default Email;
