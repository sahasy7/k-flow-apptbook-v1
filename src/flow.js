/**
 * Server-driven WhatsApp Flow with:
 * - APPOINTMENT (name/email/website/company/date/time)
 * - DETAILS (extra notes)
 * - SUMMARY (creates Cal.com booking and returns meeting URL/time)
 */

import axios from "axios";

// === Cal.com config ===
// Put these in your .env file in real usage:
// CAL_API_KEY=cal_xxx
// CAL_EVENT_TYPE_ID=3144943
const CAL_API_KEY =
  process.env.CAL_API_KEY;
const CAL_API_BASE_URL = "https://api.cal.com/v2";
const CAL_SLOTS_API_VERSION = "2024-09-04";
const CAL_BOOKING_API_VERSION = "2024-08-13"; // from your Python sample
const CAL_EVENT_TYPE_ID = process.env.CAL_EVENT_TYPE_ID;
const CAL_TIME_ZONE = "Asia/Kolkata"; // change if you want

// ---------- SERVER-DRIVEN SCREENS ----------
const SCREEN_RESPONSES = {
  APPOINTMENT: {
    screen: "APPOINTMENT",
    data: {
      name: "",
      email: "",
      website: "",
      company: "",

      // date dropdown (we’ll fill dynamically)
      date: [],
      is_date_enabled: true, // date should be enabled from the start

      // fallback time list if Cal.com fails
      time: [
        { id: "10:30", title: "10:30" },
        { id: "11:00", title: "11:00", enabled: false },
        { id: "11:30", title: "11:30" },
        { id: "12:00", title: "12:00", enabled: false },
        { id: "12:30", title: "12:30" },
      ],
      is_time_enabled: false, // enabled only after date is chosen
    },
  },
  DETAILS: {
    screen: "DETAILS",
    data: {
      name: "",
      email: "",
      website: "",
      company: "",
      date: "",
      time: "",
    },
  },
  SUMMARY: {
    screen: "SUMMARY",
    data: {
      appointment:
        "Meeting with John Doe from Example Corp (example.com)\nMon Jan 01 2024 at 11:30.",
      details:
        "Name: John Doe\nEmail: john@example.com\nWebsite: https://example.com\nCompany: Example Corp\n\nLooking forward to the call.",
      name: "John Doe",
      email: "john@example.com",
      website: "https://example.com",
      company: "Example Corp",
      date: "2024-01-01",
      time: "11:30",
      more_details: "Looking forward to the call.",
    },
  },
  TERMS: {
    screen: "TERMS",
    data: {},
  },
  SUCCESS: {
    screen: "SUCCESS",
    data: {
      extension_message_response: {
        params: {
          flow_token: "REPLACE_FLOW_TOKEN",
        },
      },
    },
  },
};

// ---------- HELPERS ----------

// Generate next 5 days for date dropdown
function getNextFiveDaysDateOptions() {
  const options = [];
  const today = new Date();

  for (let i = 0; i < 5; i++) {
    const d = new Date(today);
    d.setDate(today.getDate() + i);

    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    const id = `${year}-${month}-${day}`; // "YYYY-MM-DD"
    const title = d.toDateString(); // e.g. "Sun Nov 16 2025"

    options.push({ id, title });
  }

  return options;
}

// Fetch available time slots from Cal.com for the selected date
async function getAvailableTimeSlotsForDate(dateId) {
  if (!CAL_API_KEY) {
    console.warn("CAL_API_KEY is not set. Using static time list.");
    return SCREEN_RESPONSES.APPOINTMENT.data.time;
  }

  try {
    const response = await axios.get(`${CAL_API_BASE_URL}/slots`, {
      headers: {
        Authorization: `Bearer ${CAL_API_KEY}`,
        "cal-api-version": CAL_SLOTS_API_VERSION,
      },
      params: {
        eventTypeId: CAL_EVENT_TYPE_ID,
        start: dateId,
        end: dateId,
        timeZone: CAL_TIME_ZONE,
        format: "time",
      },
    });

    const apiData = response.data?.data || {};

    // Try exact date key first, fall back to first key if needed
    let slotsForDate = apiData[dateId];
    if (!slotsForDate) {
      const keys = Object.keys(apiData);
      const firstKey = keys.length > 0 ? keys[0] : null;
      slotsForDate = firstKey ? apiData[firstKey] : [];
    }

    if (!slotsForDate || slotsForDate.length === 0) {
      console.log(`No Cal.com slots for date ${dateId}, using static times`);
      return SCREEN_RESPONSES.APPOINTMENT.data.time;
    }

    // Convert Cal.com slot → time options for WhatsApp dropdown
    return slotsForDate.map((slot) => {
      // e.g. "2025-11-17T05:00:00.000Z" or "2025-11-17T10:30:00+05:30"
      const start = slot.start;
      const timePart = start.split("T")[1].slice(0, 5); // "HH:MM"

      return {
        id: timePart,
        title: timePart,
      };
    });
  } catch (error) {
    console.error(
      "Error fetching Cal.com slots:",
      error?.response?.data || error.message
    );
    return SCREEN_RESPONSES.APPOINTMENT.data.time;
  }
}

// Create a booking in Cal.com using final form data
async function createBooking(normalizedData) {
  if (!CAL_API_KEY) {
    console.warn("CAL_API_KEY is not set, skipping Cal.com booking.");
    return null;
  }

  try {
    const { name, email, date, time } = normalizedData;

    if (!name || !email || !date || !time) {
      console.warn("Missing data for booking:", { name, email, date, time });
      return null;
    }

    // Construct Cal.com start: "YYYY-MM-DDTHH:MM:SS+05:30"
    const start = `${date}T${time}:00.000+05:30`;

    const url = `${CAL_API_BASE_URL}/bookings`;

    const params = {
      apiKey: CAL_API_KEY,
    };

    const payload = {
      start,
      attendee: {
        name,
        email,
        timeZone: CAL_TIME_ZONE,
      },
      eventTypeId: Number(CAL_EVENT_TYPE_ID),
    };

    console.log("📤 Sending booking to Cal.com:", payload);

    const response = await axios.post(url, payload, {
      params,
      headers: {
        "Content-Type": "application/json",
        "cal-api-version": CAL_BOOKING_API_VERSION,
      },
    });

    console.log("📥 Cal.com booking response:", response.data);
    return response.data;
  } catch (err) {
    console.error(
      "❌ Cal.com booking error:",
      err.response?.data || err.message
    );
    return null;
  }
}

// ---------- MAIN HANDLER ----------

export const getNextScreen = async (decryptedBody) => {
  const { screen, data, action, flow_token } = decryptedBody;

  console.log("💬 Decrypted body:", JSON.stringify(decryptedBody, null, 2));

  // normalize possible field names
  const normalizedData = {
    ...data,
    date: data?.date || data?.Choose_your_date_d483b0,
  };

  // Health check
  if (action === "ping") {
    return { data: { status: "active" } };
  }

  // Client-side error from UI
  if (normalizedData?.error) {
    console.warn("Received client error:", normalizedData);
    return { data: { acknowledged: true } };
  }

  // First open of the flow
  if (action === "INIT") {
    const dateOptions = getNextFiveDaysDateOptions();

    return {
      ...SCREEN_RESPONSES.APPOINTMENT,
      data: {
        ...SCREEN_RESPONSES.APPOINTMENT.data,
        date: dateOptions,
        is_date_enabled: true,
        is_time_enabled: false,
      },
    };
  }

  // Main interaction
  if (action === "data_exchange") {
    switch (screen) {
      // User is interacting with APPOINTMENT screen
      case "APPOINTMENT": {
        const dateOptions = getNextFiveDaysDateOptions();

        let timeOptions = [];
        if (normalizedData?.date) {
          timeOptions = await getAvailableTimeSlotsForDate(normalizedData.date);
        }

        return {
          ...SCREEN_RESPONSES.APPOINTMENT,
          data: {
            ...SCREEN_RESPONSES.APPOINTMENT.data,

            name: normalizedData.name || "",
            email: normalizedData.email || "",
            website: normalizedData.website || "",
            company: normalizedData.company || "",

            date: dateOptions,
            is_date_enabled: true,
            is_time_enabled: Boolean(normalizedData.date),
            time: timeOptions,
          },
        };
      }

      // User submitted DETAILS screen
      case "DETAILS": {
        let dateName = normalizedData.date;
        try {
          if (normalizedData.date) {
            const d = new Date(normalizedData.date);
            if (!isNaN(d.getTime())) {
              dateName = d.toDateString();
            }
          }
        } catch {
          // ignore parse error
        }

        const appointment = `Meeting with ${
          normalizedData.name || "Guest"
        } from ${normalizedData.company || "your company"} (${
          normalizedData.website || "website not provided"
        })
${dateName} at ${normalizedData.time}`;

        const details = `Name: ${normalizedData.name}
Email: ${normalizedData.email}
Website: ${normalizedData.website}
Company: ${normalizedData.company}
"${normalizedData.more_details || ""}"`;

        return {
          ...SCREEN_RESPONSES.SUMMARY,
          data: {
            appointment,
            details,
            ...normalizedData,
          },
        };
      }

      // User confirmed on SUMMARY screen
      case "SUMMARY": {
        // Create booking on Cal.com
        const bookingResponse = await createBooking(normalizedData);

        let confirmationMessage =
          "Your details have been submitted. We'll get back to you shortly.";
        let meetingUrl = null;
        let bookingId = null;
        let meetingTimeUtc = null;
        let meetingTimeIst = null;

        if (
          bookingResponse &&
          bookingResponse.status === "success" &&
          bookingResponse.data
        ) {
          const b = bookingResponse.data;
          bookingId = b.id;
          meetingUrl = b.meetingUrl || b.location || null;
          meetingTimeUtc = b.start; // e.g. "2025-11-17T05:00:00.000Z"

          // Convert UTC → IST for nice display
          try {
            if (meetingTimeUtc) {
              const d = new Date(meetingTimeUtc); // UTC
              meetingTimeIst = d.toLocaleString("en-IN", {
                timeZone: CAL_TIME_ZONE,
                year: "numeric",
                month: "short",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
              }); // "17 Nov 2025, 10:30 AM"
            }
          } catch (e) {
            console.warn("Failed to convert meeting time to IST:", e);
          }

          confirmationMessage = "Your meeting is booked.";

          if (meetingTimeIst) {
            confirmationMessage += `\nTime (IST): ${meetingTimeIst}`;
          } else {
            confirmationMessage += `\nTime: ${normalizedData.date} ${normalizedData.time}`;
          }

          if (meetingUrl) {
            confirmationMessage += `\nMeeting link: ${meetingUrl}`;
          }
        } else {
          confirmationMessage =
            "We could not create the booking automatically, but your details were received.";
        }

        return {
          ...SCREEN_RESPONSES.SUCCESS,
          data: {
            extension_message_response: {
              params: {
                flow_token,

                // WhatsApp bot/template can use these:
                confirmation_message: confirmationMessage,
                booking_id: bookingId,
                meeting_url: meetingUrl,
                meeting_time_utc: meetingTimeUtc,
                meeting_time_ist: meetingTimeIst,

                // Original form fields
                name: normalizedData.name,
                email: normalizedData.email,
                website: normalizedData.website,
                company: normalizedData.company,
                date: normalizedData.date,
                time: normalizedData.time,
              },
            },
          },
        };
      }

      default:
        console.error("Unhandled screen:", screen);
        return { data: { acknowledged: true } };
    }
  }

  console.error("Unhandled request body:", decryptedBody);
  throw new Error(
    "Unhandled endpoint request. Make sure you handle the request action & screen logged above."
  );
};
