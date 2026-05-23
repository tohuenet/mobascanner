import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle at .next/standalone so the Docker
  // runtime stage can ship Node + the build artifact without the dev
  // node_modules tree. Drops several hundred MB off the final image.
  output: "standalone",
};

export default nextConfig;
