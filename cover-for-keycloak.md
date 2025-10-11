# Keycloak-js と oidc-client-ts の違いまとめ  
（OIDCモックサーバーを Keycloak-js に対応させたい場合）

---

## 🧩 結論（ざっくり要約）

| 比較項目 | `keycloak-js` | `oidc-client-ts` |
|-----------|----------------|------------------|
| 想定サーバー | **Keycloak専用** | **OIDC標準対応（どのIdPでも可）** |
| 設定方法 | Realm/Client設定をURLで直指定 | `.well-known/openid-configuration`を自動読込 |
| トークン処理 | Keycloak固有のエンドポイント構造前提 | OIDC標準のトークンエンドポイントに対応 |
| ログイン／ログアウト | Keycloak独自のリダイレクト形式 | 標準の`authorize`/`end_session`対応 |
| ユーザー情報 | `/realms/{realm}/protocol/openid-connect/userinfo`固定 | `.well-known`内URLに従う |
| 認可フロー | Implicit + Code(PKCE)（ただしKeycloak流） | Code + PKCE（完全に標準） |
| 相互運用性 | Keycloak専用 | Auth0 / Google / Cognito / OktaなどOK |
| 想定利用者 | Keycloak環境下のSPA | どんなOIDC IdPでも動かしたいSPA |

---

## 🔍 詳細比較

### ① エンドポイント構造の違い

**Keycloak-js** は固定パス構造を前提としています：

```
{authServerUrl}/realms/{realm}/protocol/openid-connect/auth
{authServerUrl}/realms/{realm}/protocol/openid-connect/token
{authServerUrl}/realms/{realm}/protocol/openid-connect/logout
```

**oidc-client-ts** は `.well-known/openid-configuration` から自動検出します：

```json
{
  "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
  "token_endpoint": "https://idp.example.com/oauth2/token",
  "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
  "end_session_endpoint": "https://idp.example.com/oauth2/logout"
}
```

👉 Keycloak-jsは `.well-known` を無視し、  
Keycloak特有のパスを **ハードコード的に構築** します。

---

### ② Discoveryドキュメントの扱い

- `oidc-client-ts` → `.well-known/openid-configuration` 必須  
- `keycloak-js` → `.well-known` を参照せず、独自設定を使用：

```js
const keycloak = new Keycloak({
  url: "https://keycloak.example.com/auth",
  realm: "myrealm",
  clientId: "myclient"
});
```

ここから `protocol/openid-connect/...` のURLを自動生成します。

---

### ③ 認可フローの違い

- **Keycloak-js**：Implicit Flow＋Code（PKCE）をサポートするが、実装はKeycloak依存。  
- **oidc-client-ts**：OIDC標準仕様どおり（Code＋PKCE必須、state/nonce厳密処理）。

Keycloak-jsはKeycloak前提の省略や自動生成が多く、  
他のIdPでは正しく動かないことがあります。

---

### ④ ログアウト処理の違い

Keycloak独自のログアウトURL：

```
/realms/{realm}/protocol/openid-connect/logout?redirect_uri={app}
```

標準OIDCのログアウトURL：

```
end_session_endpoint?post_logout_redirect_uri={app}
```

👉 モックサーバーでは、Keycloak風の構造に合わせる必要があります。

---

## ⚙️ Keycloak-js が期待するモックサーバー仕様（最低限）

| 機能 | 期待されるエンドポイント | 備考 |
|------|------------------|------|
| 認可コード発行 | `/realms/{realm}/protocol/openid-connect/auth` | クエリで client_id, redirect_uri, response_type=code |
| トークン発行 | `/realms/{realm}/protocol/openid-connect/token` | code → access_token, refresh_token |
| ユーザー情報 | `/realms/{realm}/protocol/openid-connect/userinfo` | Authorization: Bearer 付き |
| ログアウト | `/realms/{realm}/protocol/openid-connect/logout` | redirect_uri対応（post_logout_redirect_uriではない） |

**つまり、「/realms/.../protocol/openid-connect」構造を持つモックを立てれば動作可能**。

---

## 💡 開発ヒント

モックOIDCサーバーを自作／改造する場合：
- `/realms/:realm/protocol/openid-connect/*` のURLルーティングを再現
- 各エンドポイントで返すJSONを、Keycloakが返す形式に合わせる（例：`token_type`, `id_token`, `refresh_token_expires_in`など）

確認コマンド例：

```
curl https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration
```

→ Keycloakがどんなレスポンス形式を返すか確認できる。

---

## 🔚 まとめ

| 目的 | 推奨方法 |
|------|------------|
| Keycloak-jsを使い続けたい | モックサーバー側をKeycloak風にする（URL構造・レスポンス模倣） |
| 汎用OIDCに対応させたい | Keycloak-jsをやめて`oidc-client-ts`へ移行 |
| 両対応にしたい | Keycloakモード／OIDC標準モードを切り替え可能にする（難易度高） |
