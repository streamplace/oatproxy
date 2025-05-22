import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import createOAuthClient from "./oauth-client";
import { OAuthClient } from "@atproto/oauth-client-browser";
import { Agent } from "@atproto/api";
import { ProfileViewDetailed } from "@atproto/api/dist/client/types/app/bsky/actor/defs";

async function login(client: OAuthClient, handle: string) {
  const res = await client.authorize(handle);
  document.location.href = res.toString();
}

function App() {
  const [client, setClient] = useState<OAuthClient | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [profile, setProfile] = useState<ProfileViewDetailed | null>(null);

  useEffect(() => {
    createOAuthClient(`https://${window.location.host}`)
      .then(setClient)
      .catch(console.error);
  }, []);

  useEffect(() => {
    (async () => {
      const params = new URLSearchParams(window.location.search);
      const code = params.get("code");
      if (client && code) {
        const res = await client.callback(params);
        setAgent(new Agent(res.session));
      }
    })();
  }, [client]);

  useEffect(() => {
    (async () => {
      if (agent) {
        const res = await agent.getProfile({ actor: "scumb.ag" });
        setProfile(res.data);
      }
    })();
  }, [agent]);

  if (profile) {
    return (
      <div>
        <h1>Profile</h1>
        <img src={profile.avatar} alt="Avatar" width={100} height={100} />
        <h2>{profile.displayName}</h2>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>OATProxy Example</h1>
        {!client ? (
          <p>Loading...</p>
        ) : (
          <button onClick={() => login(client, "scumb.ag")}>Login</button>
        )}
      </header>
    </div>
  );
}

export default App;

const root = ReactDOM.createRoot(document.querySelector("main")!);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
