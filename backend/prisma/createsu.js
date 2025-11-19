/*
 * Complete this script so that it is able to add a superuser to the database
 * Usage example:
 *   node prisma/createsu.js clive123 clive.su@mail.utoronto.ca SuperUser123!
 */
"use strict";

const { PrismaClient, RoleType } = require("@prisma/client");
const prisma = new PrismaClient();
const jwt = require("jsonwebtoken");

(async () => {
  const [utorid, email, password] = process.argv.slice(2);

  // const payload = {
  //   utorid: utorid,
  //   email: email,
  //   role: RoleType.superuser,
  // };

  // const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
  // const expiresAt = new Date(
  //   Date.now() + 7 * 24 * 60 * 60 * 1000
  // ).toISOString();

  const user = await prisma.user.create({
    data: {
      utorid,
      email,
      name: "superuser",
      password: password,
      role: RoleType.superuser,
      verified: true,
      lastLogin: new Date(Date.now()).toISOString(),
      // resetToken: token,
      // expiresAt: expiresAt,
    },
  });

  console.log("Superuser created:", { utorid: user.utorid, email: user.email });
})();
