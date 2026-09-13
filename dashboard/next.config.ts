import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  // This app lives in a subdirectory of a repository that is mostly Python
  // and Go. Pinning the Turbopack root keeps resolution and file watching
  // scoped here rather than inferred from whatever lockfile Next finds
  // first if an npm command is ever run from the repository root.
  turbopack: {
    root: path.resolve(__dirname),
  },
  // The dev overlay badge sits in the bottom-left corner, exactly where this
  // app puts its backend-connectivity indicator, and covers it. Compile and
  // runtime errors are still surfaced without it.
  devIndicators: false,
};

export default nextConfig;
