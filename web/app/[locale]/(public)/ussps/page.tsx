import { UsspList } from "@/src/public/UsspList";
import { titled } from "@/src/i18n/metadata";

// The national USSP list (/public/v1/ussp_list).
export const generateMetadata = titled("cisp.ussps.title");

export default function UsspsPage() {
  return <UsspList />;
}
