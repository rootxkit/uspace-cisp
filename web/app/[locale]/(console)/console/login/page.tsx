import { LoginPage } from "@/src/console/LoginPage";
import { titled } from "@/src/i18n/metadata";

// The console's sign-in (WP-11): the password, then the TOTP code when
// the API asks for it, through the BFF's /_bff/login.
export const generateMetadata = titled("cisp.console.login.title");

export default function ConsoleLogin() {
  return <LoginPage />;
}
