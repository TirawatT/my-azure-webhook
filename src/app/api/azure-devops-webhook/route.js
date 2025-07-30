// app/api/azure-devops-webhook/route.js

import { NextResponse } from "next/server"; // ใช้ NextResponse สำหรับการส่ง HTTP response

// กำหนดให้ Route นี้เป็นแบบ Dynamic เพื่อให้รับ Request ใหม่เสมอ
// และไม่แคช Response (สำคัญสำหรับ Webhook)
export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function POST(request) {
  // 1. ตรวจสอบ method ของ HTTP request
  // Webhook ส่วนใหญ่จะส่งเป็น POST request
  // App Router จะแยก handler ตาม HTTP method โดยอัตโนมัติ (เช่น POST, GET, PUT)
  // ดังนั้นเราไม่จำเป็นต้องตรวจสอบ if (req.method !== 'POST') ซ้ำอีก
  console.log("Received a POST request to the Azure DevOps Webhook endpoint.");

  // 2. รับข้อมูล Payload จาก Azure DevOps
  // สำหรับ App Router, ใช้ request.json() เพื่อ parse JSON body
  let payload;
  try {
    payload = await request.json();
  } catch (error) {
    console.error("Error parsing request body as JSON:", error);
    return NextResponse.json(
      { message: "Invalid JSON payload.", error: error.message },
      { status: 400 }
    );
  }

  // 3. (Optional แต่แนะนำอย่างยิ่ง) ตรวจสอบความถูกต้องของ Webhook
  // Azure DevOps สามารถส่ง HTTP header เพื่อยืนยันว่าเป็น request ที่ถูกต้อง
  const headers = request.headers;
  const eventType = headers.get("x-azure-devops-event");
  const subscriptionId = headers.get("x-azure-devops-subscription-id");
  const signature = headers.get("x-azure-devops-signature"); // สำหรับการยืนยันที่ซับซ้อนขึ้น

  console.log(`Webhook Event Type: ${eventType || "N/A"}`);
  console.log(`Subscription ID: ${subscriptionId || "N/A"}`);

  // --- ตัวอย่างการตรวจสอบ Shared Secret (แนะนำอย่างยิ่ง) ---
  // คุณต้องตั้งค่า Shared Secret ใน Azure DevOps Service Hook
  // และเก็บค่านี้ไว้ใน Environment Variable ของ Next.js App
  const WEBHOOK_SECRET = process.env.AZURE_DEVOPS_WEBHOOK_SECRET;
  if (WEBHOOK_SECRET) {
    // Note: การตรวจสอบ Shared Secret ที่เหมาะสมจะใช้ HMAC SHA-256
    // แต่สำหรับการตรวจสอบอย่างง่าย คุณสามารถเปรียบเทียบค่าใน Header ได้
    // Azure DevOps ไม่ได้ส่ง 'Authorization' header สำหรับ shared secret โดยตรงเหมือน GitHub
    // คุณจะต้องกำหนด Custom HTTP Header ใน Azure DevOps Service Hook
    // เช่น Header Name: 'X-My-Secret', Value: 'YOUR_SECRET_KEY'
    const customSecretHeader = headers.get("x-my-secret");
    if (customSecretHeader !== WEBHOOK_SECRET) {
      console.warn("Unauthorized request: Secret mismatch.");
      return NextResponse.json(
        { message: "Unauthorized: Invalid secret." },
        { status: 401 }
      );
    }
  }
  // --------------------------------------------------------

  // 4. ประมวลผล Payload
  // ตัวอย่าง: การประมวลผล Advanced Security Alert
  if (eventType === "ms.advancedSecurity.alert.created") {
    const alert = payload.resource;
    if (alert) {
      console.log(`--- New Advanced Security Alert Detected ---`);
      console.log(`  Rule: ${alert.ruleName || "N/A"}`);
      console.log(
        `  Severity: ${alert.severity ? alert.severity.toUpperCase() : "N/A"}`
      );
      console.log(
        `  Repository: ${alert.repository ? alert.repository.name : "N/A"}`
      );
      console.log(`  Branch: ${alert.branch || "N/A"}`);
      console.log(
        `  File: ${alert.location ? alert.location.path : "N/A"} (Line: ${
          alert.location ? alert.location.line : "N/A"
        })`
      );
      console.log(`  Alert URL: ${alert.url || "N/A"}`);
      console.log(`------------------------------------------`);

      // --- ตัวอย่างการส่งอีเมล หรือเรียกใช้ API ภายนอก ---
      // คุณจะต้องติดตั้งไลบรารีส่งอีเมล (เช่น Nodemailer) หรือใช้บริการอีเมลภายนอก (เช่น SendGrid, Mailgun)
      // หรือเรียกใช้ Azure Function/Logic App ตัวอื่นที่ทำหน้าที่ส่งอีเมล
      try {
        await sendEmailNotification({
          subject: `[${
            alert.severity ? alert.severity.toUpperCase() : "UNKNOWN"
          }] New ADO Security Alert: ${alert.ruleName}`,
          body: `
            <p>A new Advanced Security alert has been detected:</p>
            <ul>
              <li>**Rule:** ${alert.ruleName}</li>
              <li>**Severity:** ${alert.severity.toUpperCase()}</li>
              <li>**Repository:** ${alert.repository.name}</li>
              <li>**Branch:** ${alert.branch}</li>
              <li>**Location:** ${alert.location.path} (Line: ${
            alert.location.line
          })</li>
            </ul>
            <p><a href="${alert.url}">View Alert Details in Azure DevOps</a></p>
            <p>Please investigate this alert immediately.</p>
          `,
        });
        console.log("Email notification sent successfully.");
      } catch (emailError) {
        console.error("Failed to send email notification:", emailError);
        // ไม่ส่ง error กลับไปให้ Azure DevOps เพราะ Webhook ได้รับ payload แล้ว
        // และเพื่อไม่ให้มีการ retry ซ้ำซ้อน
      }
      // --------------------------------------------------------------
    } else {
      console.warn(
        'Advanced Security alert created event received, but "resource" object is missing in payload.'
      );
    }
  } else if (eventType === "ms.vss-code.git-push-event") {
    // ตัวอย่าง: หากคุณตั้งค่า webhook สำหรับ Git Push Event
    console.log(
      `Git Push Event by ${payload.resource.pushedBy.displayName} to ${payload.resource.repository.name}`
    );
  } else {
    // เหตุการณ์อื่น ๆ ที่คุณไม่ได้สนใจ
    console.log(`Unhandled event type: ${eventType}`);
  }

  // 5. ส่งสถานะตอบกลับไปยัง Azure DevOps
  // Azure DevOps คาดหวัง HTTP 200 OK เพื่อยืนยันว่าได้รับ Payload แล้ว
  // หากไม่ส่ง 200 อาจจะมีการ Retry เกิดขึ้น
  return NextResponse.json(
    { message: "Webhook received successfully!" },
    { status: 200 }
  );
}

// --- Helper function สำหรับส่งอีเมล (คุณต้องนำไปปรับใช้จริง) ---
async function sendEmailNotification({ subject, body }) {
  // นี่คือส่วนที่คุณจะรวมโค้ดสำหรับการส่งอีเมลจริง
  // เช่น การใช้ Nodemailer:
  /*
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
      auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
      },
  });

  await transporter.sendMail({
      from: process.env.SENDER_EMAIL_ADDRESS,
      to: process.env.RECIPIENT_EMAIL_ADDRESS,
      subject: subject,
      html: body,
  });
  */
  console.log(`Attempting to send email: Subject: "${subject}"`);
  // Simulate email sending delay
  // await new Promise(resolve => setTimeout(resolve, 100));
}
