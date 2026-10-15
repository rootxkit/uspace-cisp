import { AccountsPage } from "@/src/console/AccountsPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.accounts");

export default function Accounts() {
  return <AccountsPage />;
}
