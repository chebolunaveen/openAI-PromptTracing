import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PromptTrace",
  description: "Security observability for AI agents"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
