//  CREATE TABLE seats (
//      id SERIAL PRIMARY KEY,
//      name VARCHAR(255),
//      isbooked INT DEFAULT 0
//  );
// INSERT INTO seats (isbooked)
// SELECT 0 FROM generate_series(1, 20);

import "dotenv/config";
import express from "express";
import pg from "pg";
import { dirname } from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import authRoutes from "./src/modules/auth/auth.routes.js";
import cookieParser from "cookie-parser";
import { authenticate } from "./src/modules/auth/auth.middleware.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const port = process.env.PORT || 8080;

// Equivalent to mongoose connection
// Pool is nothing but group of connections
// If you pick one connection out of the pool and release it
// the pooler will keep that connection open for sometime to other clients to reuse
const pool = new pg.Pool({
  host: "localhost",
  port: 5433,
  user: "postgres",
  password: "postgres",
  database: "sql_class_2_db",
  max: 20,
  connectionTimeoutMillis: 0,
  idleTimeoutMillis: 0,
});

const app = new express();

app.use(express.json());
app.use(cookieParser());
app.use(cors());

app.use("/api/auth", authRoutes);


app.use(express.static("public"));

//get all seats
app.get("/seats", async (req, res) => {
  const result = await pool.query("select * from seats"); // equivalent to Seats.find() in mongoose
  res.send(result.rows);
});

//book a seat give the seatId and your name

app.put("/seats/:id", authenticate, async (req, res) => {
  try {
    const id = req.params.id;
    const name = req.user.name;

    const conn = await pool.connect();
    await conn.query("BEGIN");

    const sql =
      "SELECT * FROM seats where id = $1 and isbooked = 0 FOR UPDATE";
    const result = await conn.query(sql, [id]);

    if (result.rowCount === 0) {
      await conn.query("ROLLBACK");
      conn.release();
      return res.status(400).json({ error: "Seat already booked" });
    }

    const sqlU =
      "update seats set isbooked = 1, name = $2 where id = $1";
    const updateResult = await conn.query(sqlU, [id, name]);

    await conn.query("COMMIT");
    conn.release();

    res.json({ message: "Seat booked successfully", data: updateResult });
  } catch (ex) {
    console.log(ex);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/reset-seats", async (req, res) => {
  await pool.query("UPDATE seats SET isbooked = 0, name = NULL");
  res.json({ message: "All seats reset" });
});
app.listen(port, () => console.log("Server starting on port: " + port));
