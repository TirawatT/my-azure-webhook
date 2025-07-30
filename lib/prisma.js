// prisma.js
import { PrismaClient } from "@prisma/client"; // Assuming @prisma/client is installed
import { withAccelerate } from "@prisma/extension-accelerate"; // Assuming @prisma/extension-accelerate is installed

// In Node.js, 'global' is the global object.
// We're casting it to 'any' to avoid TypeScript errors,
// but in plain JavaScript, you just access properties directly.
const globalForPrisma = global;

// Check if a PrismaClient instance already exists on the global object.
// If not, create a new one and extend it with Accelerate.
const prisma =
  globalForPrisma.prisma || new PrismaClient().$extends(withAccelerate());

// In development, store the PrismaClient instance on the global object
// to prevent hot-reloading from creating new instances on every reload.
if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

export default prisma;
