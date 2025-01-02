import express, { Request, Response } from "express";
import MariaDB from "mariadb";
import cors from "cors";
import dotenv from "dotenv"; // 환경 변수 사용한 민감한 정보 관리
import axios from "axios"; // HTTP 요청을 위한 라이브러리

// .env 파일 로드
dotenv.config();

const PORT = 3010; // 서버가 실행될 포트 번호

const app = express();
app.use(cors()); // CORS 미들웨어 추가
app.use(express.json()); // JSON 요청을 처리하기 위한 미들웨어

// MariaDB 연결
const db = MariaDB.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  connectionLimit: 10,
});

// MariaDB 연결 확인
db.getConnection()
  .then((conn) => {
    console.log("데이터베이스가 성공적으로 연결되었습니다");
    conn.release();
  })
  .catch((err) => {
    console.error("데이터베이스 연결에 실패하였습니다.", err.message);
  });

// 기본 라우트 설정
app.get("/", (req, res) => {
  res.send("FabLab Booking System Web Server!");
});

// 서버 시작
app.listen(PORT, "0.0.0.0", () => {
  console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});

// ----------------- API 라우트 -----------------
