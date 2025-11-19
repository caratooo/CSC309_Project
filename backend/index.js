#!/usr/bin/env node
"use strict";

const { PrismaClient, RoleType, TransactionType } = require("@prisma/client");
const prisma = new PrismaClient();
const jwt = require("jsonwebtoken");
require("dotenv").config();
const rateLimiter = require("./middleware/rateLimiter");
const jwtAuth = require("./middleware/jwtAuth");

const port = (() => {
  const args = process.argv;

  if (args.length !== 3) {
    console.error("usage: node index.js port");
    process.exit(1);
  }

  const num = parseInt(args[2], 10);
  if (isNaN(num)) {
    console.error("error: argument must be an integer.");
    process.exit(1);
  }

  return num;
})();

const express = require("express");
const { increment } = require("effect/MutableRef");
const { patch } = require("effect/Differ");
const app = express();

app.use(express.json());

app.post("/users", jwtAuth, async (req, res) => {
  const { utorid, name, email } = req.body;

  if (
    typeof utorid !== "string" ||
    typeof name !== "string" ||
    typeof email !== "string" ||
    !/^[a-zA-Z0-9]{7,8}$/.test(utorid) ||
    name.length < 1 ||
    name.length > 50 ||
    !/^[^\s@]+@mail\.utoronto\.ca$/.test(email)
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (
    ![RoleType.cashier, RoleType.manager, RoleType.superuser].includes(
      req.user.role
    )
  ) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const existing = await prisma.user.findUnique({
    where: { utorid: utorid },
  });

  if (existing) {
    return res.status(409).json({ message: "Conflict" });
  }

  const payload = {
    utorid: utorid,
    name: name,
    email: email,
    role: RoleType.regular,
  };

  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
  const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000
  ).toISOString();

  const newUser = await prisma.user.create({
    data: {
      utorid: utorid,
      email: email,
      name: name,
      resetToken: token,
      expiresAt: expiresAt,
    },
    select: {
      id: true,
      utorid: true,
      name: true,
      email: true,
      verified: true,
      expiresAt: true,
      resetToken: true,
    },
  });
  res.status(201).json(newUser);
});

app.get("/users", jwtAuth, async (req, res) => {
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const { name, role } = req.query;

  const verified =
    req.query.verified === "true"
      ? true
      : req.query.verified === "false"
      ? false
      : undefined;
  const activated =
    req.query.activated === "true"
      ? true
      : req.query.activated === "false"
      ? false
      : undefined;

  const page = parseInt(req.query.page) || 1;
  const take = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * take;

  if (page < 0 || take < 0 || skip < 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const filters = {};

  if (typeof name === "string" && name !== "") {
    filters.OR = [{ name: { contains: name } }, { utorid: { contains: name } }];
  }
  if (role) filters.role = role;
  if (verified !== undefined) filters.verified = verified;
  if (activated !== undefined) {
    filters.lastLogin = activated ? { not: null } : null;
  }

  const [users, count] = await Promise.all([
    prisma.user.findMany({
      where: filters,
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        lastLogin: true,
        verified: true,
        avatarUrl: true,
      },
      skip,
      take,
    }),
    prisma.user.count({ where: filters }),
  ]);

  res.status(200).json({ count, results: users });
});

app.patch("/users/me", jwtAuth, async (req, res) => {
  if (
    ![
      RoleType.regular,
      RoleType.cashier,
      RoleType.manager,
      RoleType.superuser,
    ].includes(req.user.role)
  ) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const user = await prisma.user.findUnique({
    where: {
      utorid: req.user.utorid,
    },
  });

  if (!user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const { name, email, birthday, avatar } = req.body;

  if (
    name &&
    (typeof name !== "string" || name.length < 1 || name.length > 50)
  ) {
    return res.status(400).json({ message: "Bad Request: Invalid name" });
  }

  if (email && !/^[^\s@]+@mail\.utoronto\.ca$/.test(email)) {
    return res.status(400).json({ message: "Bad Request: Invalid UofT email" });
  }

  if (birthday !== undefined) {
    if (typeof birthday !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(birthday)) {
      return res
        .status(400)
        .json({ message: "Bad Request: Invalid birthday format" });
    }

    const [yStr, mStr, dStr] = birthday.split("-");
    const year = Number(yStr),
      month = Number(mStr),
      day = Number(dStr);

    const bdayUTC = Date.UTC(year, month - 1, day);
    const dateObj = new Date(bdayUTC);

    const isSame =
      dateObj.getUTCFullYear() === year &&
      dateObj.getUTCMonth() + 1 === month &&
      dateObj.getUTCDate() === day;
    if (!isSame) {
      return res
        .status(400)
        .json({ message: "Bad Request: Invalid birthday format" });
    }

    const now = new Date();
    const todayUTC = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate()
    );
    if (bdayUTC >= todayUTC) {
      return res.status(400).json({
        message: "Bad Request: Invalid birthday format",
      });
    }
  }

  if (avatar && typeof avatar !== "string") {
    return res
      .status(400)
      .json({ message: "Bad Request: Invalid avatar format" });
  }

  const data = {};
  if (name) data.name = name;
  if (email) data.email = email;
  if (birthday) data.birthday = birthday;
  if (avatar) data.avatarUrl = avatar;

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ message: "Bad Request: empty payload" });
  }

  const updatedUser = await prisma.user.update({
    where: {
      utorid: req.user.utorid,
    },
    data: data,
    select: {
      id: true,
      utorid: true,
      name: true,
      email: true,
      birthday: true,
      role: true,
      points: true,
      createdAt: true,
      lastLogin: true,
      verified: true,
      avatarUrl: true,
    },
  });

  res.status(200).json(updatedUser);
});

app.get("/users/me", jwtAuth, async (req, res) => {
  if (
    ![
      RoleType.regular,
      RoleType.cashier,
      RoleType.manager,
      RoleType.superuser,
    ].includes(req.user.role)
  ) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const user = await prisma.user.findUnique({
    where: {
      utorid: req.user.utorid,
    },
    select: {
      id: true,
      utorid: true,
      name: true,
      email: true,
      birthday: true,
      role: true,
      points: true,
      createdAt: true,
      lastLogin: true,
      verified: true,
      avatarUrl: true,
      promotions: true,
    },
  });

  if (!user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  res.status(200).json(user);
});

app.patch("/users/me/password", jwtAuth, async (req, res) => {
  if (
    ![
      RoleType.regular,
      RoleType.cashier,
      RoleType.manager,
      RoleType.superuser,
    ].includes(req.user.role)
  ) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const user = await prisma.user.findUnique({
    where: {
      utorid: req.user.utorid,
    },
  });

  if (!user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const { old: oldpwd, new: newpwd } = req.body;

  if (
    !oldpwd ||
    !newpwd ||
    typeof oldpwd !== "string" ||
    typeof newpwd !== "string" ||
    !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,20}$/.test(newpwd)
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (user.password !== oldpwd) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const updatedUser = await prisma.user.update({
    where: {
      utorid: req.user.utorid,
    },
    data: {
      password: newpwd,
    },
  });

  res.status(200).json({ message: "OK" });
});

app.get("/users/:userId", jwtAuth, async (req, res) => {
  if (
    ![RoleType.cashier, RoleType.manager, RoleType.superuser].includes(
      req.user.role
    )
  ) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const id = Number.parseInt(req.params.userId);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const select = {
    id: true,
    utorid: true,
    name: true,
    points: true,
    verified: true,
    email: true,
  };

  if (req.user.role === RoleType.cashier) {
    select.unusedPromotion = true;
  } else {
    select.birthday = true;
    select.role = true;
    select.createdAt = true;
    select.lastLogin = true;
    select.avatarUrl = true;
    select.promotions = true;
  }

  const user = await prisma.user.findUnique({
    where: {
      id: id,
    },
    select: select,
  });

  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  res.status(200).json(user);
});

app.patch("/users/:userId", jwtAuth, async (req, res) => {
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const id = Number.parseInt(req.params.userId);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const user = await prisma.user.findUnique({
    where: { id: id },
  });

  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  const { email, verified, suspicious, role } = req.body ?? {};

  if (email) {
    if (
      typeof email !== "string" ||
      !/^[^\s@]+@mail\.utoronto\.ca$/.test(email)
    ) {
      return res.status(400).json({ message: "Bad Request: invalid email" });
    }
  }

  if (verified !== undefined && verified !== null) {
    if (typeof verified !== "boolean" || verified === false) {
      return res
        .status(400)
        .json({ message: "Bad Request: invalid verified value" });
    }
  }

  if (
    suspicious !== undefined &&
    suspicious !== null &&
    typeof suspicious !== "boolean"
  ) {
    return res
      .status(400)
      .json({ message: "Bad Request: invalid suspicious value" });
  }

  const allRoles = Object.values(RoleType);
  if (role) {
    if (typeof role !== "string" || !allRoles.includes(role)) {
      return res.status(400).json({ message: "Bad Request: invalid role" });
    }
    if (
      req.user.role === RoleType.manager &&
      ![RoleType.cashier, RoleType.regular].includes(role)
    ) {
      return res.status(403).json({
        message:
          "Forbidden: managers can only set role to 'cashier' or 'regular'",
      });
    }
  }

  if (
    user.role === RoleType.regular &&
    role === RoleType.cashier &&
    user.suspicious === true
  ) {
    return res
      .status(400)
      .json({ message: "Bad Request: suspicious user cannot be a cashier" });
  }

  const data = {};
  if (email) data.email = email;
  if (verified) data.verified = true;
  if (suspicious !== undefined && suspicious !== null)
    data.suspicious = suspicious;
  if (role) data.role = role;

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ message: "Bad Request: empty payload" });
  }

  const updated = await prisma.user.update({
    where: { id: id },
    data,
    select: {
      id: true,
      utorid: true,
      name: true,
      email: true,
      verified: true,
      suspicious: true,
      role: true,
    },
  });

  const response = {
    id: updated.id,
    utorid: updated.utorid,
    name: updated.name,
  };
  if ("email" in data) response.email = updated.email;
  if ("verified" in data) response.verified = updated.verified;
  if ("suspicious" in data) response.suspicious = updated.suspicious;
  if ("role" in data) response.role = updated.role;

  res.status(200).json(response);
});

app.post("/auth/tokens", async (req, res) => {
  const { utorid, password } = req.body;

  if (!utorid || !password) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const user = await prisma.user.findUnique({
    where: { utorid: utorid },
  });

  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const payload = {
    utorid: utorid,
    password: password,
    role: user.role,
  };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });

  const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000
  ).toISOString();

  const updatedUser = await prisma.user.update({
    where: { utorid: utorid },
    data: {
      resetToken: token,
      expiresAt: expiresAt,
      lastLogin: new Date(Date.now()).toISOString(),
    },
  });

  res.status(200).json({ token, expiresAt });
});

app.post("/auth/resets", async (req, res) => {
  const { utorid } = req.body;

  if (!utorid) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const payload = {
    utorid: utorid,
  };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });

  const expiresAt = new Date(Date.now() + 1 * 60 * 60 * 1000).toISOString();

  const user = await prisma.user.findUnique({
    where: { utorid: utorid },
  });

  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  const updatedUser = await prisma.user.update({
    where: { utorid: utorid },
    data: {
      resetToken: token,
      expiresAt: expiresAt,
      consumedAt: null,
    },
    select: {
      resetToken: true,
      expiresAt: true,
    },
  });

  res.status(202).json(updatedUser);
});

app.post("/auth/resets/:resetToken", async (req, res) => {
  const allowedFields = ["utorid", "password"];
  const bodyKeys = Object.keys(req.body);
  const extraFields = bodyKeys.filter((key) => !allowedFields.includes(key));
  if (extraFields.length > 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const { utorid, password } = req.body;
  const { resetToken } = req.params;

  if (
    !utorid ||
    !password ||
    !resetToken ||
    !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,20}$/.test(password)
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const user = await prisma.user.findUnique({
    where: { utorid: utorid },
  });

  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  let payload;
  try {
    payload = jwt.verify(resetToken, process.env.JWT_SECRET);
    req.user = payload;
  } catch (e) {
    return res.status(404).json({ message: "Bad Request: Invalid Token" });
  }

  if (req.user.utorid != user.utorid) {
    return res
      .status(401)
      .json({ message: "Unauthorized: token user doesn't match" });
  }

  if (!user.resetToken || user.resetToken !== resetToken) {
    return res.status(404).json({ message: "Not Found" });
  }

  if (new Date(user.expiresAt).getTime() < Date.now() || user.consumedAt) {
    return res.status(410).json({ message: "Gone" });
  }

  const updatedUser = await prisma.user.update({
    where: { utorid: utorid },
    data: {
      password: password,
      consumedAt: new Date(Date.now()).toISOString(),
    },
  });

  res.status(200).json({ message: "OK" });
});

// events
app.post("/events", jwtAuth, async (req, res) => {
  
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const {
    name,
    description,
    location,
    startTime,
    endTime,
    capacity,
    points
  } = req.body;

  if (!name || !description || !location || !startTime || !endTime || points === undefined) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (
    typeof name !== "string" ||
    typeof description !== "string" ||
    typeof location !== "string" ||
    typeof startTime !== "string" ||
    typeof endTime !== "string" ||
    !Number.isInteger(points) ||
    points <= 0
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (capacity !== undefined && capacity !== null) {
    if (!Number.isInteger(capacity) || capacity <= 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
  }

  const startDate = new Date(startTime);
  const endDate = new Date(endTime);
  
  if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (startDate >= endDate) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const newEvent = await prisma.event.create({
    data: { 
      name,
      description,
      location,
      startTime: startDate.toISOString(),
      endTime: endDate.toISOString(),
      capacity: capacity || null,
      pointsRemain: points,
      pointsAwarded: 0,
      published: false,
      numGuests: 0
    },
    include: {
      organizers: {
        select: {
          id: true,
          utorid: true,
          name: true
        }
      },
      guests: {
        select: {
          id: true,
          utorid: true,
          name: true
        }
      }
    }
  });

  res.status(201).json(newEvent);
  
});

app.get("/events", jwtAuth, async (req, res) => {

  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const { name, location } = req.query;

  const started = req.query.started === "true"
    ? true
    : req.query.started === "false"
    ? false
    : undefined;
  
  const ended = req.query.ended === "true"
    ? true
    : req.query.ended === "false"
    ? false
    : undefined;
  
  const showFull = req.query.showFull === "true"
    ? true
    : req.query.showFull === "false"
    ? false
    : undefined; 

  if (req.query.page !== null) {
    if (req.query.page < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
  }

  if (req.query.limit !== null) {
    if (req.query.limit < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
  }

  const page = parseInt(req.query.page) || 1;
  const take = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * take;

  const filters = {};

  if (typeof name === "string" && name !== "") {
    filters.name = {
      contains: name,
      mode: 'insensitive'
    };
  }

  if (typeof location === "string" && location !== "") {
    filters.location = {
      contains: location,
      mode: 'insensitive'
    };
  }

  // filter dates
  const now = new Date();
  if (started !== undefined) {
    if (started) {
      filters.startTime = { lte: now.toISOString() };
    } else {
      filters.startTime = { gt: now.toISOString() };
    }
  }

  if (ended !== undefined) {
    if (ended) {
      filters.endTime = { lte: now.toISOString() };
    } else {
      filters.endTime = { gt: now.toISOString() };
    }
  }

  if (ended !== undefined && started !== undefined) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const select = {
    id: true,
    name: true,
    location: true,
    startTime: true,
    endTime: true,
    capacity: true,
    numGuests: true
  };

  if (req.user.role === RoleType.regular || req.user.role === RoleType.cashier) {
    filters.published = true;
  }

  else if (req.user.role === RoleType.manager || req.user.role === RoleType.superuser) {
    
    select.pointsRemain = true;
    select.pointsAwarded = true;
    select.published = true;

    const published = req.query.published === "true"
      ? true
      : req.query.published === "false"
      ? false
      : undefined;

    if (published !== undefined) {
      filters.published = published;
    }

  }

  // When showFull filter is applied, we need to fetch all events first, then filter
  const needsShowFullFilter = showFull !== undefined;

  const [allEvents, totalCount] = await Promise.all([
    prisma.event.findMany({
      where: filters,
      select: select,
      skip: needsShowFullFilter ? 0 : skip,
      take: needsShowFullFilter ? undefined : take
    }),
    prisma.event.count({
      where: filters
    })
  ]);

  let events = allEvents;
  let count = totalCount;

  if (showFull !== undefined) {

    if (showFull === false) {
      // Filter out full events (keep only non-full events)
      events = allEvents.filter(event => {
        if (event.capacity === null) {
          // Events with no capacity limit are never considered "full"
          return true;
        }
        return event.numGuests < event.capacity;
      });
    }
    // If showFull === true, show all events (no filtering needed)
    
    count = events.length;

    // Apply pagination after filtering
    events = events.slice(skip, skip + take);
  }

  res.status(200).json({ count, results: events });

});

app.get("/events/:eventId", jwtAuth, async (req, res) => {

  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const eventId = Number.parseInt(req.params.eventId);

  if (!Number.isInteger(eventId) || eventId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // First, get the event to check if user is an organizer
  const eventCheck = await prisma.event.findUnique({
    where: { id: eventId },
    select: {
      id: true,
      published: true,
      organizers: {
        select: {
          utorid: true
        }
      }
    }
  });

  if (!eventCheck) {
    return res.status(404).json({ message: "Not Found" });
  }

  // Check if user is an organizer of this event
  const isOrganizer = eventCheck.organizers.some(organizer => organizer.utorid === req.user.utorid);
  
  // Determine access level: manager/superuser OR organizer
  const hasManagerAccess = req.user.role === RoleType.manager || req.user.role === RoleType.superuser || isOrganizer;

  const select = {
    id: true,
    name: true,
    description: true,
    location: true,
    startTime: true,
    endTime: true,
    capacity: true,
    organizers: {
      select: {
        id: true,
        utorid: true,
        name: true
      }
    }
  };

  const where = { id: eventId };

  if (!hasManagerAccess) {
    // Regular users and cashiers (who are not organizers)
    select.numGuests = true;
    where.published = true; // Only show published events to regular/cashier users
  } else {
    // Managers, superusers, or organizers
    select.pointsRemain = true;
    select.pointsAwarded = true;
    select.published = true;
    select.guests = {
      select: {
        id: true,
        utorid: true,
        name: true
      }
    };
  }

  const event = await prisma.event.findUnique({
    where: where,
    select: select
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  res.status(200).json(event);
});

app.patch("/events/:eventId", jwtAuth, async (req, res) => {

  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const eventId = Number.parseInt(req.params.eventId);

  if (!Number.isInteger(eventId) || eventId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const eventCheck = await prisma.event.findUnique({
    where: { id: eventId },
    select: {
      id: true,
      published: true,
      organizers: {
        select: {
          utorid: true
        }
      }
    }
  });

  if (!eventCheck) {
    return res.status(404).json({ message: "Not Found" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId }
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  const { name, description, location, startTime, endTime, capacity, points, published } = req.body ?? {};
  const data = {};

  if (name !== undefined && name !== null) {
    if (typeof name !== "string") {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.name = name;
  }

  if (description !== undefined && description !== null) {
    if (typeof description !== "string") {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.description = description;
  }

  if (location !== undefined && location !== null) {
    if (typeof location !== "string") {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.location = location;
  }

  if (startTime !== undefined && startTime !== null) {
    if (typeof startTime !== "string") {
      return res.status(400).json({ message: "Bad Request" });
    }
    const startDate = new Date(startTime);
    if (isNaN(startDate.getTime()) || startDate < new Date()) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.startTime = startDate.toISOString();
  }

  if (endTime !== undefined && endTime !== null) {
    if (typeof endTime !== "string") {
      return res.status(400).json({ message: "Bad Request" });
    }
    const endDate = new Date(endTime);
    const startTimeToUse = startTime ? new Date(startTime) : new Date(event.startTime);
    if (isNaN(endDate.getTime()) || endDate <= startTimeToUse || endDate < new Date()) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.endTime = endDate.toISOString();
  }

  if (capacity !== undefined) {
    if (capacity !== null) {
      // Convert string to number if needed
      const capacityNum = parseInt(capacity);
      const currentGuests = event.numGuests || 0;
      if (!Number.isInteger(capacityNum) || capacityNum <= 0 || capacityNum < currentGuests) {
        return res.status(400).json({ message: "Bad Request" });
      }
      data.capacity = capacityNum;
    }
  }

  if (points !== undefined && points !== null) {
    if (![RoleType.manager].includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    const pointsNum = parseInt(points);
    if (!Number.isInteger(pointsNum) || pointsNum < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    const pointsRemain = pointsNum - event.pointsAwarded;
    if (pointsRemain < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.pointsRemain = pointsRemain;
  }

  if (published !== undefined && published !== null) {
    if (![RoleType.manager].includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    // Convert string to boolean if needed
    let publishedBool;
    if (typeof published === "string") {
      publishedBool = published.toLowerCase() === "true";
    } else if (typeof published === "boolean") {
      publishedBool = published;
    } else {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.published = publishedBool;
  }

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ message: "Bad Request: empty payload" });
  }

  if (name || description || location || startTime || (capacity !== undefined && capacity !== null)) {
    // if original start time has passed
    if (new Date(event.startTime) <= new Date()) {
      return res.status(400).json({ message: "Bad Request" });
    }
  }

  const updatedEvent = await prisma.event.update({
    where: { id: eventId },
    data: data
  });

  const response = {
    id: updatedEvent.id,
    name: updatedEvent.name,
    location: updatedEvent.location
  };
  if ("description" in data) response.description = updatedEvent.description;
  if ("startTime" in data) response.startTime = updatedEvent.startTime;
  if ("endTime" in data) response.endTime = updatedEvent.endTime;
  if ("capacity" in data) response.capacity = updatedEvent.capacity;
  if ("pointsRemain" in data) {
    response.pointsRemain = updatedEvent.pointsRemain;
    response.pointsAwarded = updatedEvent.pointsAwarded;
  }
  if ("published" in data) response.published = updatedEvent.published;

  res.status(200).json(response);

});


app.delete("/events/:eventId", jwtAuth, async (req, res) => {
  // needs to be manager or above
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const eventId = Number.parseInt(req.params.eventId);

  if (!Number.isInteger(eventId) || eventId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  if (event.published === true) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // delete event
  await prisma.event.delete({
    where: { id: eventId },
  });

  res.status(204).json({ message: "No Content" });

});

app.post("/events/:eventId/organizers", jwtAuth, async (req, res) => {
  // needs to be manager or above
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const eventId = Number.parseInt(req.params.eventId);
  const { utorid } = req.body;

  if (!Number.isInteger(eventId) || eventId <= 0 || !utorid || typeof utorid !== "string") {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      guests: true,
      organizers: true
    }
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  if (event.endTime <= new Date()) {
    return res.status(410).json({ message: "Gone" });
  }

  // check if user exists
  const user = await prisma.user.findUnique({
    where: { utorid: utorid }
  });

  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if user is already a guest of event
  if (event.guests.some(guest => guest.utorid === utorid)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // check if user is already an organizer of event
  if (event.organizers.some(organizer => organizer.utorid === utorid)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // Add the organizer
  const updatedEvent = await prisma.event.update({
    where: { id: eventId },
    data: {
      organizers: {
        connect: { utorid: utorid }
      }
    },
    include: {
      organizers: {
        select: {
          id: true,
          utorid: true,
          name: true
        }
      }
    }
  });

  res.status(201).json({
    id: updatedEvent.id,
    name: updatedEvent.name,
    location: updatedEvent.location,
    organizers: updatedEvent.organizers
  });

});

app.delete("/events/:eventId/organizers/:userId", jwtAuth, async (req, res) => {

  // needs to be manager or above
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const eventId = Number.parseInt(req.params.eventId);
  const userId = Number.parseInt(req.params.userId);

  if (!Number.isInteger(eventId) || eventId <= 0 || !Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      organizers: true
    }
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if user is an organizer of event
  if (!event.organizers.some(organizer => organizer.id === userId)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // Remove the organizer
  await prisma.event.update({
    where: { id: eventId },
    data: {
      organizers: {
        disconnect: { id: userId }
      }
    }
  });

  res.status(204).json({ message: "No Content" });

});

app.post("/events/:eventId/guests", jwtAuth, async (req, res) => {

  const eventId = Number.parseInt(req.params.eventId);
  const { utorid } = req.body;

  if (!Number.isInteger(eventId) || eventId <= 0 || !utorid || typeof utorid !== "string") {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      guests: true,
      organizers: true
    } 
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if organizer
  const isOrganizer = event.organizers.some(organizer => organizer.utorid === req.user.utorid);
  // needs to be manager or above or organizer
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role) && !isOrganizer) {
    return res.status(403).json({ message: "Forbidden" });
  }

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if user exists
  const user = await prisma.user.findUnique({
    where: { utorid: utorid }
  });
  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  // event isn't published
  if (event.published === false) {
    return res.status(404).json({ message: "Not Found" });
  }

  // event is full
  if (event.capacity !== null && event.numGuests >= event.capacity) {
    return res.status(410).json({ message: "Gone" });
  }

  // event has ended
  if (event.endTime <= new Date()) {
    return res.status(410).json({ message: "Gone" });
  }

  // check if user is already a guest of event
  if (event.guests.some(guest => guest.utorid === utorid)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // check if user is an organizer of event
  if (event.organizers.some(organizer => organizer.utorid === utorid)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // Add the guest
  const updatedEvent = await prisma.event.update({
    where: { id: eventId },
    data: {
      guests: {
        connect: { utorid: utorid }
      },
      numGuests: { increment: 1 }
    },
    include: {
      guests: {
        select: {
          id: true,
          utorid: true,
          name: true
        }
      }
    }
  });

  res.status(201).json({
    id: updatedEvent.id,
    name: updatedEvent.name,
    location: updatedEvent.location,
    guestAdded: {
      id: user.id,
      utorid: user.utorid,
      name: user.name
    },
    numGuests: updatedEvent.numGuests
  });

});

app.post("/events/:eventId/guests/me", jwtAuth, async (req, res) => {

  const eventId = Number.parseInt(req.params.eventId);

  if (!Number.isInteger(eventId) || eventId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      guests: true,
      organizers: true
    }
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  // event isn't published
  if (event.published === false) {
    return res.status(404).json({ message: "Not Found" });
  }

  // event is full
  if (event.capacity !== null && event.numGuests >= event.capacity) {
    return res.status(410).json({ message: "Gone" });
  }

  // event has ended
  if (event.endTime <= new Date()) {
    return res.status(410).json({ message: "Gone" });
  }

  // check if user is already a guest of event
  if (event.guests.some(guest => guest.utorid === req.user.utorid)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // check if user is an organizer of event
  if (event.organizers.some(organizer => organizer.utorid === req.user.utorid)) {
    return res.status(400).json({ message: "Bad Request" });
  }

  // Get user details for response
  const user = await prisma.user.findUnique({
    where: { utorid: req.user.utorid },
    select: {
      id: true,
      utorid: true,
      name: true
    }
  });

  if (!user) {
    return res.status(404).json({ message: "Not Found" });
  }

  // Add the guest
  const updatedEvent = await prisma.event.update({
    where: { id: eventId },
    data: {
      guests: {
        connect: { utorid: req.user.utorid }
      },
      numGuests: { increment: 1 }
    },
    include: {
      guests: {
        select: {
          id: true,
          utorid: true,
          name: true
        }
      }
    }
  });

  res.status(201).json({
    id: updatedEvent.id,
    name: updatedEvent.name,
    location: updatedEvent.location,
    guestAdded: {
      id: user.id,
      utorid: user.utorid,
      name: user.name
    },
    numGuests: updatedEvent.numGuests
  });

});

app.delete("/events/:eventId/guests/me", jwtAuth, async (req, res) => {

  const eventId = Number.parseInt(req.params.eventId);

  if (!Number.isInteger(eventId) || eventId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      guests: true
    }
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if user is a guest of event
  if (!event.guests.some(guest => guest.utorid === req.user.utorid)) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if event has ended
  if (event.endTime <= new Date()) {
    return res.status(410).json({ message: "Gone" });
  }

  // remove the guest
  await prisma.event.update({
    where: { id: eventId },
    data: {
      guests: {
        disconnect: { utorid: req.user.utorid }
      },
      numGuests: { decrement: 1 }
    }
  });

  res.status(204).json({ message: "No Content" });

});

app.delete("/events/:eventId/guests/:userId", jwtAuth, async (req, res) => {

  // only managers or above
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }
  
  const eventId = Number.parseInt(req.params.eventId);
  const userId = Number.parseInt(req.params.userId);

  if (!Number.isInteger(eventId) || eventId <= 0 || !Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      guests: true
    }
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if user is a guest of event
  if (!event.guests.some(guest => guest.id === userId)) {
    return res.status(404).json({ message: "Not Found" });
  }

  // check if event has ended
  if (event.endTime <= new Date()) {
    return res.status(410).json({ message: "Gone" });
  }

  // Remove the guest
  await prisma.event.update({
    where: { id: eventId },
    data: {
      guests: {
        disconnect: { id: userId }
      },
      numGuests: { decrement: 1 }
    }
  });

  res.status(204).json({ message: "No Content" });

});

app.post("/events/:eventId/transactions", jwtAuth, async (req, res) => {
  const eventId = Number.parseInt(req.params.eventId, 10);

  if (!Number.isInteger(eventId) || eventId <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const event = await prisma.event.findUnique({
    where: { id: eventId },
    include: {
      organizers: { select: { utorid: true } },
      guests: { select: { utorid: true } },
    },
  });

  if (!event) {
    return res.status(404).json({ message: "Not Found" });
  }

  const isOrganizer = event.organizers.some(
    (u) => u.utorid === req.user.utorid
  );

  if (
    !isOrganizer &&
    ![RoleType.manager, RoleType.superuser].includes(req.user.role)
  ) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const { type, utorid } = req.body;

  const amount = Number.parseInt(req.body?.amount, 10);

  if (!amount || !Number.isInteger(amount) || amount <= 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (type !== "event" || (utorid && typeof utorid != "string")) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const toResponse = (transaction) => ({
    id: transaction.id,
    recipient: transaction.utorid,
    awarded: transaction.earned,
    type: transaction.type,
    relatedId: transaction.relatedId,
    remark: transaction.remark,
    createdBy: transaction.createdBy,
  });

  // specific utorid
  if (utorid) {
    const onGuestList = event.guests.some((g) => g.utorid === utorid);
    if (!onGuestList) {
      return res.status(400).json({ message: "Bad Request" });
    }

    if (event.pointsRemain < amount) {
      return res.status(400).json({ message: "Bad Request" });
    }

    const rewardedUser = await prisma.user.update({
      where: {
        utorid: utorid,
      },
      data: {
        points: { increment: amount },
      },
    });

    const updatedEvent = await prisma.event.update({
      where: {
        id: eventId,
      },
      data: {
        pointsRemain: { decrement: amount },
        pointsAwarded: { increment: amount }
      },
    });

    // Creating transaction
    const transaction = await prisma.transaction.create({
      data: {
        utorid: utorid,
        type: TransactionType.event,
        amount: amount,
        earned: amount,
        remark: event.description,
        createdBy: req.user.utorid,
        processedBy: req.user.utorid,
        relatedId: eventId,
      },
    });

    return res.status(201).json(toResponse(transaction));
  }

  // No specified utorid
  const guestUtorids = event.guests.map((g) => g.utorid);
  if (guestUtorids.length === 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const requiredPoints = amount * guestUtorids.length;
  if (event.pointsRemain < requiredPoints) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const rewardedUsers = await prisma.user.updateMany({
    where: {
      utorid: { in: guestUtorids },
    },
    data: {
      points: { increment: amount },
    },
  });

  const updatedEvent = await prisma.event.update({
    where: {
      id: eventId,
    },
    data: {
      pointsRemain: { decrement: requiredPoints },
      pointsAwarded: { increment: requiredPoints },
    },
  });

  const transactions = [];
  for (const guestId of guestUtorids) {
    const guest = await prisma.user.findUnique({
      where: {
        utorid: guestId,
      },
    });

    const transaction = await prisma.transaction.create({
      data: {
        utorid: guestId,
        type: TransactionType.event,
        amount: amount,
        earned: amount,
        remark: event.description,
        createdBy: req.user.utorid,
        processedBy: req.user.utorid,
        relatedId: eventId,
      },
    });
    transactions.push(transaction);
  }

  res.status(201).json(transactions.map(toResponse));
});

// Transactions
async function purchaseTransaction(req, res) {
  if (![RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const allowedParams = [
    "utorid",
    "type",
    "spent",
    "promotionIds",
    "remark"
  ];
  
  for (const key of Object.keys(req.body)) {
    if (!allowedParams.includes(key)) {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  const {utorid, type, spent, promotionIds, remark} = req.body;

  if (
    typeof utorid !== "string" ||
    type !== "purchase" ||
    typeof spent !== "number" ||
    spent <= 0 ||
    (promotionIds !== undefined && !Array.isArray(promotionIds)) ||
    (remark !== undefined && typeof remark !== "string")
  ){
    return res.status(400).json({ "error": "Bad Request" });
  }

  const user = await prisma.user.findUnique({
    where: {utorid: utorid},
    include: { promotions: true }
  });

  if (!user) {
    return res.status(404).json({ "error": "User not found" });
  }

  const promotions = await prisma.promotion.findMany({
    where: {
      id: {in: promotionIds || []}
    }
  });

  if (promotions.length !== (promotionIds || []).length) {
    return res.status(400).json({"error": "One or more promotions not found" });
  }

  let totalPoints = Math.round(spent/0.25);

  await prisma.$transaction(async (prisma) => {
    const now = new Date();
    for (let promo of promotions) {
      const st = new Date(promo.startTime);
      const et = new Date(promo.endTime);

      if (st.getTime() > now.getTime() || et.getTime() < now.getTime()){
        return res.status(400).json({"error": "Promotion error"});
      }
      
      if (promo.minSpending !== null && spent < promo.minSpending) {
        return res.status(400).json({"error": "Spent amount does not meet promotion requirement"});
      }

      if (promo.type === "onetime") {
        if (user.promotions.find(p => p.id === promo.id)){
          return res.status(400).json({"error": "Promotion used" });
        }

        await prisma.user.update({
          where: { utorid: utorid },
          data: {
            promotions: {connect: {id: promo.id}}
          }})
      }
      
      if (promo.points){
        totalPoints += promo.points;
      }
      if (promo.rate){
        totalPoints += spent* (promo.rate * 100);
      }
    }

    totalPoints = Math.round(totalPoints);


    const cashier = await prisma.user.findUnique({
      where: { utorid: req.user.utorid }
    });

    let promotionsData;
    if (promotionIds && promotionIds.length > 0) {
      promotionsData = {connect: promotionIds.map(id => ({id}))};
    }

    const newTransaction = await prisma.transaction.create({
      data: {
        utorid: utorid,
        type: type,
        spent: spent,
        earned: totalPoints,
        amount: totalPoints,
        remark: remark || "",
        promotions: promotionsData,
        createdBy: req.user.utorid,
        suspicious: cashier.suspicious,
      },
    });

    if (!cashier.suspicious) {
      await prisma.user.update({
        where: { utorid: utorid },
        data: {
          points: { increment: totalPoints }
        }
      });
    }
    
    let actualEarned;
    if (cashier.suspicious){
      actualEarned = 0;
    }
    else{
      actualEarned = totalPoints;
    }

    res.status(201).json({  
      "id": newTransaction.id,
      "utorid": newTransaction.utorid,
      "type": newTransaction.type,
      "spent": newTransaction.spent,
      "earned": actualEarned,
      "remark": newTransaction.remark,
      "promotionIds": promotionIds || [],
      "createdBy": newTransaction.createdBy
    });
  });
}

async function adjustTransaction(req, res) {
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const allowedParams = [
    "utorid",
    "type",
    "amount",
    "relatedId",
    "promotionIds",
    "remark"
  ];
  
  for (const key of Object.keys(req.body)) {
    if (!allowedParams.includes(key)) {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  const {utorid, type, amount, relatedId, promotionIds, remark} = req.body;
  if (
    typeof utorid !== "string" ||
    type !== "adjustment" ||
    typeof amount !== "number" ||
    typeof relatedId !== "number" ||  
    ((promotionIds !== undefined &&  promotionIds !== null) && !Array.isArray(promotionIds)) ||
    ((remark !== undefined && remark !== null) && typeof remark !== "string")
  ){
    return res.status(400).json({ "error": "Bad Request" });
  }

  const user = await prisma.user.findUnique({
    where: {utorid: utorid}
  });
    
  if (!user) {
    return res.status(404).json({ "error": "User not found" });
  }

  const relatedtrans = await prisma.transaction.findUnique({
    where: {id: relatedId}
  });
  
  if (!relatedtrans) {
    return res.status(404).json({ "error": "Related transaction not found" });
  }

  const promotions = await prisma.promotion.findMany({
    where: {
      id: {in: promotionIds || []}
    }
  });

  let totalPoints = amount;

  for (let promo of promotions) {
    if (promo.points){
      totalPoints += promo.points;
    }
    if (promo.rate){
      totalPoints += Math.round(amount*promo.rate);
    }
  }

  await prisma.user.update({
    where: { utorid: utorid },
    data: {
      points: { increment: totalPoints }
    }
  });

  let promotionsData;
  if (promotionIds && promotionIds.length > 0) {
    promotionsData = {connect: promotionIds.map(id => ({id}))};
  }

  const newTransaction = await prisma.transaction.create({
    data: {
      utorid: utorid,
      type: type,
      amount: amount,
      relatedId: relatedId,
      remark: remark || "",
      promotions: promotionsData,
      createdBy: req.user.utorid,
    }      
  });

  res.status(201).json({
    "id": newTransaction.id,
    "utorid": newTransaction.utorid,
    "type": newTransaction.type,
    "amount": newTransaction.amount,
    "relatedId": newTransaction.relatedId,
    "remark": newTransaction.remark,
    "promotionIds": promotionIds || [],
    "createdBy": newTransaction.createdBy
  });
}

app.post("/transactions", jwtAuth, async (req,res) => {
  if (req.body.type === "purchase") {
    return await purchaseTransaction(req, res);
  }
  else if (req.body.type === "adjustment") {
    return await adjustTransaction(req, res);
  }
});

app.get("/transactions", jwtAuth, async (req, res) => {
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const {name, createdBy, suspicious, promotionId, type, relatedId, amount, operator, page, limit} = req.query
  const filters = {};

  if (createdBy !== undefined) {
    filters.createdBy = createdBy;
  }

  if (suspicious !== undefined) {
    if (suspicious !== "true" && suspicious !== "false") {
      return res.status(400).json({ error: "Bad Request" });
    }
    filters.suspicious = suspicious === "true";
  }

  if (promotionId !== undefined) {
    if (Number.isNaN(Number(promotionId))) {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  if (type !== undefined) {
    if (!["purchase", "adjustment", "redemption", "transfer", "event"].includes(type))
    {
      return res.status(400).json({ error: "Bad Request" });
    }
    filters.type = type;
  }

  if (relatedId !== undefined) {
    if (Number.isNaN(Number(relatedId))) {
      return res.status(400).json({ error: "Bad Request" });
    }
    filters.relatedId = Number(relatedId);
  }

  if (amount !== undefined) {
    if (Number.isNaN(Number(amount))) {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  if (operator !== undefined) {
    if (operator !== "gte" && operator !== "lte") {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  let pageInt = 1;
  if (page !== undefined) {
    if (Number.isNaN(Number(page)) || Number(page) <= 0) {
      return res.status(400).json({ error: "Bad Request" });
    }
    pageInt = Number(page);
  } 

  let limitInt = 10;
  if (limit !== undefined) {
    if (Number.isNaN(Number(limit)) || Number(limit) <= 0) {
      return res.status(400).json({ error: "Bad Request" });
    }
    limitInt = Number(limit);
  } 

  if (filters.relatedId !== undefined && filters.type === undefined) {
    return res.status(400).json({ error: "relatedId requires type" });
  }
  if (amount !== undefined && operator === undefined) {
    return res.status(400).json({ error: "amount requires operator" });
  }

  if (amount !== undefined) {
    filters.amount = { [operator]: Number(amount) };
  }
  if (name !== undefined) {
    filters.OR = [
      { utorid: { contains: name} },
      { receiver: { is: {name: {contains: name}}}},
    ];
  }
  if (promotionId !== undefined) {
    filters.promotions = { some: { id: Number(promotionId) } };
  }

  const skip = (pageInt - 1) * limitInt;
  const count = await prisma.transaction.count(
    {where: filters}
  )
  let alltrans = await prisma.transaction.findMany(
    {
      where: filters,
      skip,
      take: limitInt,
      include: {promotions: {select:{id: true}}}
    }
  )

  alltrans = alltrans.map(tran =>
    Object.fromEntries(
      Object.entries(tran).filter(([_, v]) => v !== null && v !== undefined)
    )
  );

  alltrans = alltrans.map(tran => {
    const { promotions, ...rest } = tran;
    return { ...rest, promotionIds: (promotions || []).map(p => p.id) };
  });
  

  return res.status(200).json(
    {
    "count": count,
    "results": alltrans
    }
  )

});

app.get("/transactions/:transactionId", jwtAuth, async(req, res) => {
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const id = Number(req.params.transactionId);

  let tran = await prisma.transaction.findUnique(
    {
      where: {id: id}
    }
  )
  const { promotions, ...rest } = tran;

  tran = {...rest, promotionIds: (promotions || []).map(p => p.id)};
  tran = Object.fromEntries(Object.entries(tran).filter(([_, v]) => v !== null && v !== undefined))

  if (!tran){
    return res.status(403).json({"error": "No object found"})
  }
  return res.status(200).json(tran)
});

app.patch("/transactions/:transactionId/suspicious", jwtAuth, async(req, res) => {
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const {suspicious} = req.body
  let id = req.params.transactionId

  if (Number.isNaN(Number(id))) {
    return res.status(400).json({ error: "Bad Request" });
  }
  id = Number(id);

  if (suspicious === undefined || suspicious === null || Object.keys(req.body).length !== 1){
    return res.status(400).json({"error": "Bad request"});
  }

  let tran = await prisma.transaction.findUnique(
    {
      where: {id: id}
    }
  )
  if (!tran){
    return res.status(403).json({"error": "No object found"})
  }
  tran = Object.fromEntries(Object.entries(tran).filter(([_, v]) => v !== null && v !== undefined))

  if (tran.suspicious === suspicious){
    return res.status(200).json(tran)
  }

  await prisma.$transaction(async (prisma) => {
    let patchedTran = await prisma.transaction.update(
      {
        where: {id: id},
        data: {suspicious: suspicious},
        include: { promotions: { select: { id: true } } }
      }
    )
  
    if (suspicious === false){
      // from true to false
      await prisma.user.update({
        where: {utorid: patchedTran.utorid},
        data: {points: {increment: patchedTran.amount}}
      })
    }
    else{
      await prisma.user.update({
        where: {utorid: patchedTran.utorid},
        data: {points: {increment: -patchedTran.amount}}
      })
    }
  
    patchedTran = Object.fromEntries(Object.entries(patchedTran).filter(([_, v]) => v !== null && v !== undefined))
    const { promotions, ...rest } = patchedTran;
    patchedTran = { ...rest, promotionIds: (promotions || []).map(p => p.id) };

    return res.status(200).json(patchedTran)
  })
});
app.post("/users/me/transactions", jwtAuth, async (req, res) => {
  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const requiredParams = ["type", "amount", "remark"];

  for (const key of Object.keys(req.body)) {
    if (!requiredParams.includes(key)) {
      return res.status(400).json({ "error": "Bad Request" });
    }
  }

  const {type, amount, remark} = req.body;
  if (type !== "redemption") {
    return res.status(400).json({ "error": "Bad Request" });
  }
  if (typeof amount !== "number" || amount <= 0 || !Number.isFinite(amount) || Math.floor(amount) !== amount){
    return res.status(400).json({ "error": "Bad Request" });
  }
  if (remark !== undefined && typeof remark !== "string"){
    return res.status(400).json({ "error": "Bad Request" });
  }

  const user = await prisma.user.findUnique({
    where: {utorid: req.user.utorid}
  });

  if (!user) {
    return res.status(404).json({ "error": "User not found" });
  }

  if(!user.verified) {
    return res.status(403).json({ "error": "User not verified" });
  }
  if(user.points < amount) {
    return res.status(400).json({ "error": "Insufficient points" });
  }

  const tran = await prisma.transaction.create({
    data: {
      utorid: user.utorid,
      type: type,
      amount: amount,
      remark: remark,
      createdBy: user.utorid
    }
  });

  return res.status(201).json({
    "id": tran.id,
    "utorid": tran.utorid,
    "type": tran.type,
    "amount": tran.amount,
    "remark": tran.remark,
    "createdBy": tran.createdBy,
    "processedBy": tran.processedBy
  })
});

app.post("/users/:userId/transactions", jwtAuth, async (req, res) => {
  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }
  const allowedParams = ["type", "amount", "remark"];

  for(const key of Object.keys(req.body)) {
    if (!allowedParams.includes(key)) {
      return res.status(400).json({ "error": "Bad Request" });
    }
  }

  const {type, amount, remark} = req.body;
  if (type !== "transfer") {
    return res.status(400).json({ "error": "Bad Request" });
  }

  if (typeof amount !== "number" || amount <= 0){
    return res.status(400).json({ "error": "Bad Request" });
  }

  if (remark !== undefined && typeof remark !== "string"){
    return res.status(400).json({ "error": "Bad Request" });
  }

  const id = Number.parseInt(req.params.userId);
  const receiver = await prisma.user.findUnique({
    where: {id: id}
  })

  if (!receiver) {
    return res.status(404).json({ "error": "receiver not found" });
  }

  const sender = await prisma.user.findUnique({
    where: {utorid: req.user.utorid}
  })

  if (!sender) {
    return res.status(404).json({ "error": "sender not found" });
  }
  if (sender.verified === false){
    return res.status(403).json({ "error": "sender not verified" });
  }
  if (sender.points < amount){
    return res.status(400).json({ "error": "insufficient points" });
  }

  await prisma.$transaction(async (prisma) => {
    await prisma.user.update(
      {
        where: { utorid: sender.utorid },
        data: { points: { increment: -amount } }
      }
    )
  
    await prisma.user.update(
      {
        where: { id: id},
        data: { points: { increment: amount } }
      }
    )
  
    const newSendTran = await prisma.transaction.create({
      data: {
        utorid: sender.utorid,
        type : type,
        amount: amount,
        remark: remark,
        createdBy: sender.utorid,
        relatedId: receiver.id
      }
    })
  
    await prisma.transaction.create({
      data: {
        utorid: receiver.utorid,
        type : type,
        amount: amount, 
        remark: remark,
        createdBy: sender.utorid,
        relatedId: sender.id
      }
    })

    res.status(201).json({
      "id" : newSendTran.id,
      "sender": sender.utorid,
      "recipient": receiver.utorid,
      "type": newSendTran.type,
      "sent": newSendTran.amount,
      "remark": newSendTran.remark,
      "createdBy": newSendTran.createdBy,
      "email": receiver.email
    })
  })
});

app.get("/users/me/transactions", jwtAuth, async (req, res) => {
  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const {promotionId, type, relatedId, amount, operator, page, limit} = req.query
  const filters = {};
  filters.utorid = req.user.utorid;

  if (promotionId !== undefined) {
    if (Number.isNaN(Number(promotionId))) {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  if (type !== undefined) {
    if (!["purchase", "adjustment", "redemption", "transfer", "event"].includes(type))
    {
      return res.status(400).json({ error: "Bad Request" });
    }
    filters.type = type;
  }

  if (relatedId !== undefined) {
    if (Number.isNaN(Number(relatedId))) {
      return res.status(400).json({ error: "Bad Request" });
    }
    filters.relatedId = Number(relatedId);
  }

  if (amount !== undefined) {
    if (Number.isNaN(Number(amount))) {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  if (operator !== undefined) {
    if (operator !== "gte" && operator !== "lte") {
      return res.status(400).json({ error: "Bad Request" });
    }
  }

  let pageInt = 1;
  if (page !== undefined) {
    if (Number.isNaN(Number(page)) || Number(page) <= 0) {
      return res.status(400).json({ error: "Bad Request" });
    }
    pageInt = Number(page);
  } 

  let limitInt = 10;
  if (limit !== undefined) {
    if (Number.isNaN(Number(limit)) || Number(limit) <= 0) {
      return res.status(400).json({ error: "Bad Request" });
    }
    limitInt = Number(limit);
  } 

  if (filters.relatedId !== undefined && filters.type === undefined) {
    return res.status(400).json({ error: "relatedId requires type" });
  }
  if (amount !== undefined && operator === undefined) {
    return res.status(400).json({ error: "amount requires operator" });
  }

  if (amount !== undefined) {
    filters.amount = { [operator]: Number(amount) };
  }

  if (promotionId !== undefined) {
    filters.promotions = { some: { id: Number(promotionId) } };
  }

  const skip = (pageInt - 1) * limitInt;
  const count = await prisma.transaction.count(
    {where: filters}
  )
  let alltrans = await prisma.transaction.findMany(
    {
      where: filters,
      skip: skip,
      take: limitInt,
      include: {promotions: {select:{id: true}}}
    }
  )

  alltrans = alltrans.map(tran =>
    Object.fromEntries(
      Object.entries(tran).filter(([_, v]) => v !== null && v !== undefined)
    )
  );

  alltrans = alltrans.map(tran => {
    const { promotions, ...rest } = tran;
    return { ...rest, promotionIds: (promotions || []).map(p => p.id) };
  });
  

  return res.status(200).json(
    {
    "count": count,
    "results": alltrans
    }
  )
});

app.patch("/transactions/:transactionId/processed", jwtAuth, async(req, res) => {
  if (![RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({"error": "Forbidden"});
  }

  const {processed} = req.body;
  if (processed !== true){
    return res.status(400).json({"error": "Bad request"});
  }

  if (Number.isNaN(Number(req.params.transactionId))) {
    return res.status(400).json({ error: "Bad Request" });
  }
  const tranId = Number(req.params.transactionId);

  const tran = await prisma.transaction.findUnique({
    where: {id: tranId}
  });

  if(!tran) {
    return res.status(404).json({"error": "Transaction not found"});
  }

  if(tran.type !== "redemption" || tran.processedBy !== null) {
    return res.status(400).json({"error": "Bad request"});
  }

  await prisma.$transaction(async (prisma) => {
    let updateTran = await prisma.transaction.update({
      where: {id: tran.id},
      data: {processedBy: req.user.utorid}
    })

    const user = await prisma.user.findUnique({
      where: {utorid: updateTran.utorid}
    });

    await prisma.user.update({
      where: {utorid: user.utorid},
      data: {points: {increment: -updateTran.amount}}
    });
    
    updateTran = Object.fromEntries(Object.entries(updateTran).filter(([_, v]) => v !== null && v !== undefined));
    updateTran.redeemed = updateTran.amount;
    return res.status(200).json(updateTran);
  });
});

app.post("/promotions", jwtAuth, async (req,res) => {
  const {name , description, type, startTime, endTime, minSpending, rate, points} = req.body;

  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const present = new Date();
  const st = new Date(startTime);
  const et = new Date(endTime);

  if (
    typeof name !== "string" || 
    typeof description !== "string" ||
    !(type === "automatic" || type === "one-time" || type === "onetime") ||
    st.getTime() <= present.getTime() ||
    st.getTime() >= et.getTime()
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }

  let conType = "automatic";
  if (type === "one-time" || type === "onetime") {
    conType = "onetime";
  }

  if (minSpending !== undefined && (typeof minSpending !== "number" || !Number.isFinite(minSpending) || minSpending <= 0) && minSpending !== null
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (rate !== undefined && (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0) && rate !== null) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (points !== undefined && (!Number.isInteger(points) || points < 0) && points !== null
  ) {
    return res.status(400).json({ message: "Bad Request" });
  }
  
  const newPromotion = await prisma.promotion.create({
    data: { 
      name,
      description,
      type: conType,
      startTime: st.toISOString(),
      endTime: et.toISOString(),
      minSpending: minSpending || null,
      rate: rate || null,
      points: points || null
    },
    select : {
      id: true,
      name: true,
      description: true,
      type: true,
      startTime: true,
      endTime: true,
      minSpending: true,
      rate: true,
      points: true
    }
  });

  res.status(201).json(newPromotion);

});

app.get("/promotions", jwtAuth, async (req,res) => {
  
  const {name, type, page, limit} = req.query;

  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const manager_or_higher = [RoleType.manager, RoleType.superuser].includes(req.user.role);

  const pageNum = parseInt(page) || 1;
  const take = parseInt(limit) || 10;

  if (req.query.started !== undefined && req.query.ended !== undefined) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (!Number.isInteger(pageNum) || pageNum < 1|| !Number.isInteger(take) || take < 1) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const skip = (pageNum - 1) * take;
  
  if (type !== "automatic" && type !== "onetime" && type !== undefined) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const filters = {};
  
  if (typeof name === "string" && name !== "") {
    filters.name = { contains: name };
  }
  if (type) filters.type = type;

  const now = new Date();

  if (manager_or_higher) {
    if (req.query.started === "true") {
      filters.startTime = { lte : now };
    } 
    if (req.query.ended === "true") {
      filters.endTime = { lte : now };
    }
  } else {
    filters.startTime = {lte : now};
    filters.endTime = {gt : now};
  }

  const [promotions, count] = await Promise.all([
    prisma.promotion.findMany({
      where: filters,
      select: {
        id: true,
        name: true,
        description: true,
        type: true,
        startTime: true,
        endTime: true,
        minSpending: true,
        rate: true,
        points: true
      },
      skip,
      take,
    }),
    prisma.promotion.count({ where: filters }),
  ]);

  res.status(200).json({ count, results: promotions });

});


app.get("/promotions/:promotionId", jwtAuth, async (req,res) => {
  
  const promotionId = Number.parseInt(req.params.promotionId);

  const now = new Date();

  if (!Number.isInteger(promotionId) || promotionId <= 0) {
    return res.status(404).json({ message: "Not Found" });
  }

  if (![RoleType.regular, RoleType.cashier, RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const promotion = await prisma.promotion.findUnique({
    where: {
      id: promotionId,
    },
    select: {
      id: true,
      name: true,
      description: true,
      type: true,
      startTime: true,
      endTime: true,
      minSpending: true,
      rate: true,
      points: true
    },
  });

  if (!promotion) {
    return res.status(404).json({ message: "Not Found" });
  }

  const start = new Date(promotion.startTime);
  const end = new Date(promotion.endTime);

  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    if (start.getTime() > now.getTime() || end.getTime() <= now.getTime()) {
      return res.status(404).json({ message: "Not Found" });
    }
  }

  res.status(200).json(promotion);
});

app.patch("/promotions/:promotionId", jwtAuth, async (req,res) => {
  
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const {name , description, type, startTime, endTime, minSpending, rate, points} = req.body;
  const data = {};

  const promotionId = Number.parseInt(req.params.promotionId);
  if (!Number.isInteger(promotionId) || promotionId <= 0) {
    return res.status(404).json({ message: "Not Found" });
  } 

  const current = await prisma.promotion.findUnique({
    where: { id: promotionId },
    select: {
      startTime: true,
      endTime: true
    }
  });

  if (!current) {
    return res.status(404).json({ message: "Not Found" });
  }

  const now = new Date();

  if (name !== undefined && name !== null) {
    if (typeof name !== "string" || name.length === 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.name = name;
  }

  if (description !== undefined && description !== null) {
    if (typeof description !== "string" || description.length === 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.description = description;
  }

  if (type !== undefined && type !== null) {
    if (type !== "automatic" && type !== "onetime" && type !== "one-time") {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.type = type;
  }

  let st_ = new Date(current.startTime);
  let et_  = new Date(current.endTime);
  
  if (startTime !== undefined && startTime !== null) {
    const st = new Date(startTime);
    const now = new Date();
    if (st.getTime() < now.getTime()) {
      return res.status(400).json({ message: "Bad Request" });
    }
    st_ = st;
    data.startTime = st.toISOString();
  }

  if (endTime !== undefined && endTime !== null) {
    const et = new Date(endTime);
    if (et.getTime() < now.getTime()) {
      return res.status(400).json({ message: "Bad Request" });
    }
    et_ = et;
    data.endTime = et.toISOString();
  }

  if (st_ && et_ && st_.getTime() > et_.getTime()) {
    return res.status(400).json({ message: "Bad Request" });
  }

  if (minSpending !== undefined && minSpending !== null) {
    if (!Number.isInteger(minSpending) || minSpending < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.minSpending = minSpending;
  }

  if (rate !== undefined && rate !== null) {
    if (typeof rate !== "number" || !Number.isFinite(rate) || rate < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.rate = rate;
  }

  if (points !== undefined && points !== null) {
    if (!Number.isInteger(points) || points < 0) {
      return res.status(400).json({ message: "Bad Request" });
    }
    data.points = points;
  }

  if (Object.keys(data).length === 0) {
    return res.status(400).json({ message: "Bad Request" });
  }

  const updatedPromotion = await prisma.promotion.update({
    where: { id: Number.parseInt(req.params.promotionId) },
    data: data,
    select : {
      id: true,
      name: true,
      description: true,
      type: true,
      startTime: true,
      endTime: true,
      minSpending: true,
      rate: true,
      points: true
    }
  });

  res.status(200).json(updatedPromotion);

});

app.delete("/promotions/:promotionId", jwtAuth, async (req,res) => {
  
  if (![RoleType.manager, RoleType.superuser].includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }

  const promotionId = Number.parseInt(req.params.promotionId);
  if (!Number.isInteger(promotionId) || promotionId <= 0) {
    return res.status(404).json({ message: "Not Found" });
  }

  const promotion = await prisma.promotion.findUnique({
    where: { id: promotionId },
    select: {
      id: true,
      startTime: true,
    }
  });

  if (!promotion) {
    return res.status(404).json({ message: "Not Found" });
  }

  const now = new Date();
  const promotionSt= new Date(promotion.startTime);

  if (promotionSt.getTime() <= now.getTime()) {
    return res.status(403).json({ message: "Forbidden" });
  }
  
  await prisma.promotion.delete({
    where: { id: promotionId }
  });

  res.status(204).send();
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.on("error", (err) => {
  console.error(`cannot start server: ${err.message}`);
  process.exit(1);
});
