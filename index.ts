import express, { Request, Response } from "express";
import MariaDB from "mariadb";
import cors from "cors";
import dotenv from "dotenv"; // 환경 변수 사용한 민감한 정보 관리
import axios from "axios"; // HTTP 요청을 위한 라이브러리
import bcrypt from "bcrypt"; // 비밀번호 암호화 최신버전
import jwt from "jsonwebtoken";

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
  bigNumberStrings: true,
  dateStrings: false
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

// *** 사용자 로그인 API 시작 ***
app.post("/users/login", (req: Request, res: Response) => {
  const { id, password } = req.body;

  // Step 1: ID로 사용자 조회
  db.query("SELECT * FROM user WHERE id = ? AND state = 'active'", [id])
    .then((rows: any) => {
      if (rows.length === 0) {
        // 사용자가 없는 경우
        return res.status(401).json({
          success: false,
          message: "사용자를 찾을 수 없습니다. 회원가입 후 이용해주세요.",
        });
      }

      const user = rows[0];

      // Step 3: 암호화된 비밀번호 비교
      return bcrypt.compare(password, user.password).then((isPasswordMatch) => {
        if (!isPasswordMatch) {
          return res.status(401).json({
            success: false,
            message: "비밀번호가 일치하지 않습니다. 다시 입력해주세요.",
          });
        }

         // Access Token 발급
         const accessToken = jwt.sign(
          { userId: user.user_id, name: user.name, email: user.email },
          process.env.JWT_ACCESS_SECRET!,
          { expiresIn: "15m" } // Access Token 만료 시간
        );

        // Refresh Token 발급
        const refreshToken = jwt.sign(
          { userId: user.user_id },
          process.env.JWT_REFRESH_SECRET!,
          { expiresIn: "7d" } // Refresh Token 만료 시간
        );

        // Refresh Token 데이터베이스에 저장
        return db.query("UPDATE user SET token = ? WHERE id = ?", [refreshToken, id])
          .then(() => {
            res.json({
              success: true,
              message: "로그인 성공",
              accessToken,
              refreshToken,
              name: user.name,
              userId: user.user_id, // 사용자 ID, 프론트에서 사용
            });
        });
      });
    })
    .catch((err) => {
      // 에러 처리
      console.error("서버 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류 발생",
        error: err.message,
      });
    });
}); // 사용자 로그인 API 끝

// *** 사용자 회원가입 API 시작
app.post("/users/register", (req: Request, res: Response) => {
  const { name, id, email, password } = req.body as {
    name: string;     // 이름
    id: string;       // 아이디(학번)
    email: string;    // 이메일
    password: string; // 비밀번호
  };

  // Step 1: 학생 정보가 존재하는지 확인
  db.query("SELECT student_id FROM student WHERE student_id = ? and name = ?", [id, name])
    .then((rows_id: any) => {
      if (rows_id.length === 0) {
        return res
          .status(400)
          .json({ success: false, message: "해당하는 학생이 존재하지 않습니다." });
      }

      // Step 2: 비밀번호 암호화
      return bcrypt.hash(password, 10);
    })
    .then((hashedPassword: string) => {
      // Step 3: 사용자 저장
      return db.query(
        "INSERT INTO user (name, id, email, password) VALUES (?, ?, ?, ?)",
        [name, id, email, hashedPassword]
      );
    })
    .then((result: any) => {
      res
        .status(201)
        .json({ success: true, message: "사용자가 성공적으로 등록되었습니다" });
    })
    .catch((err: any) => {
      // Step 4: 에러 처리
      console.error("서버 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류 발생",
        error: err.message,
      });
    });
}); // *** 사용자 회원가입 API 끝

// *** 로그아웃 API 시작 ***
app.post("/users/logout", (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  db.query("SELECT * FROM user WHERE token = ?", [refreshToken])
    .then((rows: any[]): Promise<void> => {
      if (rows.length === 0) {
        res.status(404).json({
          success: false,
          message: "유효하지 않은 토큰입니다.",
        });
        return Promise.resolve();
      }

      // DB에서 Refresh Token 제거
      return db.query("UPDATE user SET token = NULL WHERE token = ?", [refreshToken])
        .then(() => {
          res.status(200).json({
            success: true,
            message: "로그아웃이 성공적으로 완료되었습니다.",
          });
        });
    })
    .catch((err) => {
      console.error("로그아웃 처리 중 서버 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "로그아웃 처리 중 오류가 발생했습니다.",
      });
    });
});
// *** 로그아웃 API 끝 ***

// *** 계정 탈퇴 API 시작 ***
app.patch("/users/account", (req: Request, res: Response) => {
  const { user_id } = req.body;

  db.query("UPDATE user SET state = 'inactive' WHERE user_id = ?", [user_id])
    .then((rows) => {
      res.status(200).json({
        success: true,
        message: "계정이 성공적으로 탈퇴되었습니다.",
      });
    })
    .catch((err) => {
      console.error("계정 탈퇴 처리 중 서버 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "계정 탈퇴 처리 중 오류가 발생했습니다.",
      });
    });
});
// *** 계정 탈퇴 API 끝 ***

// *** 좌석 예약 생성 API 시작 ***
app.post("/reservations", (req: Request, res: Response) => {
  const { user_id, seat_id, start_date, end_date } = req.body;

  // Step 1: 좌석 중복 확인
  db.query(
    "SELECT * FROM book WHERE seat_id = ? AND ((start_date <= ? AND end_date >= ?) OR (start_date <= ? AND end_date >= ?)) AND state = 'book'",
    [seat_id, start_date, start_date, end_date, end_date]
  )
    .then((rows: any) => {
      if (rows.length > 0) {
        return res.status(400).json({
          success: false,
          message: "해당 시간에 이미 예약된 좌석입니다.",
        });
      }

      // Step 2: 예약 생성
      return db.query(
        "INSERT INTO book (user_id, seat_id, start_date, end_date, state) VALUES (?, ?, ?, ?, 'book')",
        [user_id, seat_id, start_date, end_date]
      );
    })
    .then((result: any) => {
      res.status(201).json({
        success: true,
        reservation_id: result.insertId,
        status: "예약 완료",
      });
    })
    .catch((err) => {
      console.error("예약 생성 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 예약 생성에 실패했습니다.",
      });
    });
});
// *** 좌석 예약 생성 API 끝 ***





