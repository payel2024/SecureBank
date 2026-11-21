import express from "express";
import { randomInt } from "crypto";
import { prisma } from "../lib/prisma.js";
import { authenticate } from "../middleware/auth.js";

const router = express.Router();

// Admin-only protection
const requireAdmin = (req, res, next) => {
  if (!req.user || !["ADMIN", "SUPER_ADMIN"].includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      message: "Admin access required.",
    });
  }

  next();
};

router.use(authenticate, requireAdmin);

// Generate a unique simulated bank account number
const generateAccountNumber = () => {
  return `SB${Date.now()}${randomInt(1000, 9999)}`;
};

// 1. Create Customer and Account
router.post("/customers", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      nid,
      mobileNumber,
      email,
      accountType = "SAVINGS",
    } = req.body;

    if (!firstName || !lastName || !nid || !mobileNumber) {
      return res.status(400).json({
        success: false,
        message: "First name, last name, NID and mobile number are required.",
      });
    }

    const cleanFirstName = String(firstName).trim();
    const cleanLastName = String(lastName).trim();
    const cleanNid = String(nid).trim();
    const cleanMobile = String(mobileNumber).trim();
    const cleanEmail = email ? String(email).trim().toLowerCase() : null;

    if (
      !cleanFirstName ||
      !cleanLastName ||
      !cleanNid ||
      !/^\+?[0-9]{10,15}$/.test(cleanMobile)
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide valid customer information.",
      });
    }

    if (!["SAVINGS", "CURRENT"].includes(accountType)) {
      return res.status(400).json({
        success: false,
        message: "Invalid account type.",
      });
    }

    const customer = await prisma.$transaction(async (tx) => {
      const newCustomer = await tx.customer.create({
        data: {
          firstName: cleanFirstName,
          lastName: cleanLastName,
          fullName: `${cleanFirstName} ${cleanLastName}`,
          nid: cleanNid,
          mobileNumber: cleanMobile,
          email: cleanEmail,
          isRegistered: false,
          isActive: true,
        },
      });

      const account = await tx.account.create({
        data: {
          accountNumber: generateAccountNumber(),
          accountType,
          balance: 0,
          status: "ACTIVE",
          customerId: newCustomer.id,
          createdByAdminId: req.user.userId,
        },
      });

      await tx.securityLog.create({
        data: {
          adminId: req.user.userId,
          customerId: newCustomer.id,
          eventType: "CUSTOMER_ACCOUNT_CREATED",
          severity: "INFO",
          description: "Admin created a new customer and bank account.",
        },
      });

      return {
        ...newCustomer,
        accounts: [account],
      };
    });

    return res.status(201).json({
      success: true,
      message: "Customer and account created successfully.",
      data: customer,
    });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({
        success: false,
        message: "NID, mobile number, or email already exists.",
      });
    }

    console.error("Create customer error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create customer.",
    });
  }
});

// 2. Get all customers
router.get("/customers", async (req, res) => {
  try {
    const customers = await prisma.customer.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        accounts: {
          select: {
            accountNumber: true,
            accountType: true,
            balance: true,
            status: true,
            createdAt: true,
          },
        },
      },
    });

    return res.json({
      success: true,
      count: customers.length,
      data: customers,
    });
  } catch (error) {
    console.error("Customer list error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve customers.",
    });
  }
});

// 3. Search customer by account number
router.get("/customers/account/:accountNumber", async (req, res) => {
  try {
    const { accountNumber } = req.params;

    const account = await prisma.account.findUnique({
      where: { accountNumber },
      include: {
        customer: {
          include: {
            accounts: true,
          },
        },
        transactions: {
          orderBy: { createdAt: "desc" },
        },
      },
    });

    if (!account) {
      return res.status(404).json({
        success: false,
        message: "Account not found.",
      });
    }

    return res.json({
      success: true,
      data: account,
    });
  } catch (error) {
    console.error("Account search error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to search account.",
    });
  }
});

// 4. Get customer details by customer ID
router.get("/customers/:id", async (req, res) => {
  try {
    const customerId = Number(req.params.id);

    if (!Number.isSafeInteger(customerId) || customerId <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid customer ID.",
      });
    }

    const customer = await prisma.customer.findUnique({
      where: { id: customerId },
      include: {
        accounts: {
          include: {
            transactions: {
              orderBy: { createdAt: "desc" },
            },
          },
        },
        devices: true,
        loginRequests: true,
        securityLogs: {
          orderBy: { createdAt: "desc" },
        },
      },
    });

    if (!customer) {
      return res.status(404).json({
        success: false,
        message: "Customer not found.",
      });
    }

    return res.json({
      success: true,
      data: customer,
    });
  } catch (error) {
    console.error("Customer details error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve customer details.",
    });
  }
});


// DEVICE MONITORING: search all registered devices using a bank account number.
// Admin-only because this router is protected by authenticate + requireAdmin above.
router.get("/device-monitoring/account/:accountNumber", async (req, res) => {
  try {
    const accountNumber = String(req.params.accountNumber || "").trim();
    if (!accountNumber) {
      return res.status(400).json({ success: false, message: "Account number is required." });
    }

    const account = await prisma.account.findUnique({
      where: { accountNumber },
      include: {
        customer: {
          select: {
            id: true, fullName: true, mobileNumber: true, email: true,
            isActive: true, isLocked: true,
            devices: { orderBy: { lastUsedAt: "desc" }, select: {
              id: true, deviceName: true, fingerprintHash: true, ipAddress: true,
              browser: true, operatingSystem: true, approximateLocation: true,
              deviceType: true, browserVersion: true, screenResolution: true, language: true, timezone: true, userAgent: true,
              ipCountry: true, ipRegion: true, ipCity: true, ipIsp: true, ipLatitude: true, ipLongitude: true,
              gpsLatitude: true, gpsLongitude: true, gpsAccuracy: true, gpsPermissionStatus: true, gpsCollectedAt: true,
              status: true, isActive: true, failedAttempts: true, isLocked: true,
              lockedAt: true, createdAt: true, lastUsedAt: true
            }}
          }
        }
      }
    });

    if (!account) {
      return res.status(404).json({ success: false, message: "Account not found." });
    }

    return res.json({
      success: true,
      data: {
        accountNumber: account.accountNumber,
        accountStatus: account.status,
        customer: account.customer
      }
    });
  } catch (error) {
    console.error("Admin device monitoring search error:", error);
    return res.status(500).json({ success: false, message: "Unable to load customer device information." });
  }
});


// BLOCK / UNBLOCK CUSTOMER (admin-only). Uses the existing customer lock fields.
router.post("/customers/:id/block", async (req, res) => {
  try {
    const customerId = Number(req.params.id);
    const reason = String(req.body?.reason || "Blocked by bank administrator").trim().slice(0, 500);
    if (!Number.isSafeInteger(customerId) || customerId <= 0) return res.status(400).json({ success: false, message: "Invalid customer ID." });
    const customer = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true, fullName: true, isLocked: true } });
    if (!customer) return res.status(404).json({ success: false, message: "Customer not found." });
    await prisma.$transaction([
      prisma.customer.update({ where: { id: customerId }, data: { isLocked: true, lockedAt: new Date(), lockReason: reason || "Blocked by bank administrator" } }),
      prisma.securityLog.create({ data: { adminId: req.user.id, customerId, eventType: "CUSTOMER_BLOCKED_BY_ADMIN", severity: "HIGH", description: `Customer blocked by admin. Reason: ${reason || "Not specified"}` } })
    ]);
    return res.json({ success: true, message: "Customer blocked successfully." });
  } catch (error) {
    console.error("Customer block error:", error);
    return res.status(500).json({ success: false, message: "Unable to block customer." });
  }
});

router.post("/customers/:id/unblock", async (req, res) => {
  try {
    const customerId = Number(req.params.id);
    if (!Number.isSafeInteger(customerId) || customerId <= 0) return res.status(400).json({ success: false, message: "Invalid customer ID." });
    const customer = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
    if (!customer) return res.status(404).json({ success: false, message: "Customer not found." });
    await prisma.$transaction([
      prisma.customer.update({ where: { id: customerId }, data: { isLocked: false, lockedAt: null, lockReason: null, failedLoginAttempts: 0 } }),
      prisma.securityLog.create({ data: { adminId: req.user.id, customerId, eventType: "CUSTOMER_UNBLOCKED_BY_ADMIN", severity: "INFO", description: "Customer unblocked by admin." } })
    ]);
    return res.json({ success: true, message: "Customer unblocked successfully." });
  } catch (error) {
    console.error("Customer unblock error:", error);
    return res.status(500).json({ success: false, message: "Unable to unblock customer." });
  }
});

export default router;