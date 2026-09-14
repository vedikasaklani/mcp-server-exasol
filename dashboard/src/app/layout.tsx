import type { Metadata } from "next";
import { IBM_Plex_Mono, Saira } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { cn } from "@/lib/utils";

// Saira for interface text - a grotesque with a slight technical/engineered
// edge that suits a security console. Plex Mono is metrically distinct on
// purpose: ids, counts and syscalls should read as instrumentation, not
// prose, so they get their own typeface.
const saira = Saira({ subsets: ["latin"], variable: "--font-sans" });

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "MCP Warden",
  description: "Discovery, confinement, audit and reputation for MCP servers.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={cn("dark", "h-full", "antialiased", "font-sans", saira.variable, plexMono.variable)}
    >
      <body className="min-h-full bg-bg text-text">
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto max-w-[1600px] px-6 py-7 lg:px-10">{children}</div>
          </main>
        </div>
      </body>
    </html>
  );
}
