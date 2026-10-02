import { LoginPage } from "@/src/console/LoginPage";

// The console's sign-in (WP-11): the password, then the TOTP code when
// the API asks for it, through the BFF's /_bff/login.
export default function ConsoleLogin() {
  return <LoginPage />;
}
