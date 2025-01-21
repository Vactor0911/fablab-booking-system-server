import express, { Request, Response, NextFunction } from "express";
import MariaDB from "mariadb";
import cors from "cors";
import dotenv from "dotenv"; // 환경 변수 사용한 민감한 정보 관리
import bcrypt from "bcrypt"; // 비밀번호 암호화 최신버전
import jwt from "jsonwebtoken";

import moment from "moment-timezone"; // 시간대 변환 라이브러리

import cookieParser from "cookie-parser"; // 쿠키 파싱 미들웨어 추가
import adminRoutes from "./admin"; // 관리자 전용 API
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate"; // 인증 미들웨어

import rateLimit from "express-rate-limit"; // 요청 제한 미들웨어
import csurf from "csurf";
import validator from "validator"; // 유효성 검사 라이브러리
const allowedSymbols = /^[a-zA-Z0-9!@#$%^&*?]*$/; // 허용된 문자만 포함하는지 확인

// Request 타입 확장
declare module "express" {
  export interface Request {
    csrfToken?: () => string; // csrfToken 메서드 정의
  }
}

// Rate Limit 설정
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 요청 횟수
});

import nodemailer from "nodemailer";  // 이메일 전송 라이브러리

// .env 파일 로드
dotenv.config();
// 환경변수가 하나라도 없으면 서버 실행 불가
["DB_HOST", "DB_PORT", "DB_USERNAME", "DB_PASSWORD", "DB_DATABASE", "JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET"].forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`해당 환경변수가 존재하지 않습니다.: ${key}`);
  }
});

const PORT = 3002; // 서버가 실행될 포트 번호
const FRONT_PORT = 4000; // 프론트 서버 포트 번호

const app = express();
app.use(cors({ origin: `http://localhost:${FRONT_PORT}`, credentials: true })); // CORS 설정, credentials는 프론트와 백엔드의 쿠키 공유를 위해 필요
app.use(express.json()); // JSON 요청을 처리하기 위한 미들웨어
app.use(cookieParser()); // 쿠키 파싱 미들웨어 등록

// CSRF 미들웨어 초기화
// 원하는 경로에만 csrfProtection를 추가
// 예시 app.post("/users/logout", csrfProtection, (req: Request, res: Response) => {
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: false, // HTTPS 환경에서는 true로 설정
    sameSite: "strict", // CSRF 보호를 위한 설정
  },
});

// // 추가로 모든 POST, PATCH, PUT, DELETE에 적용하고 싶으면 미들웨어를 전역으로 추가 가능
// app.use((req: Request, res: Response, next: NextFunction) => {
//   if (["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) {
//     return csrfProtection(req, res, next);
//   }
//   next();
// });


// MariaDB 연결
export const db = MariaDB.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  connectionLimit: 30,  // 동시 접속자 수
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

// *** 라우트 정의 시작 ***

// 관리자 전용 API 연결
app.use("/admin", adminRoutes);


// *** 라우트 정의 끝 ***

// 글로벌 에러 핸들러 추가 시작
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof SyntaxError && "body" in err) {
    res.status(400).json({
      success: false,
      message: "잘못된 JSON 형식입니다.",
    });
    return;
  }

  console.error("Unhandled Error:", err);
  res.status(500).json({
    success: false,
    message: "서버 오류가 발생했습니다.",
  });
}); // 글로벌 에러 핸들러 추가 끝

// BigInt를 JSON으로 직렬화하기 위한 글로벌 함수
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};


// 서버 시작
app.listen(PORT, "0.0.0.0", () => {
  console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});


// ----------------- API 라우트 -----------------

// CSRF 토큰 요청 API 시작 *중요
app.get("/csrf-token", csrfProtection, (req: Request, res: Response) => {
  try {
    res.json({ csrfToken: req.csrfToken?.() }); // csrfToken 메서드 사용
  } catch (err) {
    console.error("CSRF 토큰 생성 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "CSRF 토큰 생성 중 오류가 발생했습니다.",
    });
  }
});
// CSRF 토큰 요청 API 끝



// *** 로그인 API 시작 ***
app.post("/users/login", csrfProtection, (req: Request, res: Response) => {
  const { id, password } = req.body;

  if (!/^\d{7,10}$/.test(id)) { // 학번은 숫자 7~10자리
    res.status(400).json({
        success: false,
        message: "학번은 숫자로만 구성된 7~10자리 값이어야 합니다.",
    });
    return;
  }

  // Step 0: 탈퇴된 계정인지 확인
  db.query("SELECT id, state FROM user WHERE id = ?", [id])
    .then((rows: any) => {
      if (rows.length > 0 && rows[0].state === "inactive") {
        // 탈퇴된 계정인 경우
        return Promise.reject({
          status: 400,
          message: "탈퇴된 계정입니다. 계정을 복구해주세요.",
        });
      }

      // Step 1: ID로 사용자 조회
      return db.query("SELECT * FROM user WHERE id = ? AND state = 'active'", [id]);
    })
    .then((rows: any) => {
      if (rows.length === 0) {
        // 사용자가 없는 경우
        return res.status(401).json({
          success: false,
          message: "사용자를 찾을 수 없습니다. 회원가입 후 이용해주세요.",
        });
      }

      const user = rows[0];

      // Step 2: 암호화된 비밀번호 비교
      return bcrypt.compare(password, user.password).then((isPasswordMatch) => {
        if (!isPasswordMatch) {
          return res.status(401).json({
            success: false,
            message: "비밀번호가 일치하지 않습니다. 다시 입력해주세요.",
          });
        }

        // Step 3: Access Token 발급
        const accessToken = jwt.sign(
          { userId: user.user_id, name: user.name, permission: user.permission },
          process.env.JWT_ACCESS_SECRET!,
          { expiresIn: "15m" } // Access Token 만료 시간
        );

        // Step 4: Refresh Token 발급
        const refreshToken = jwt.sign(
          { userId: user.user_id, name: user.name, permission: user.permission},
          process.env.JWT_REFRESH_SECRET!,
          { expiresIn: "7d" } // Refresh Token 만료 시간
        );

        // Step 5: Refresh Token 저장 (DB)
        return db.query("UPDATE user SET refreshtoken = ? WHERE id = ?", [refreshToken, id])
          .then(() => {
            // Step 6: 쿠키에 Access Token과 Refresh Token 저장
            res.cookie("accessToken", accessToken, {
              httpOnly: true,
              secure: false, // ture : HTTPS 환경에서만 작동, false : HTTP 환경에서도 작동(로컬 환경)
              sameSite: "strict", // CSRF 방지 (strict, lax, none) -> 이거 사용보다 그냥 CSRF 토큰 사용하는게 더 안전 -> 따라서 적용
              //strict : 같은 사이트에서만 쿠키 전송
              //lax : GET 요청에서만 쿠키 전송
              //none : 모든 요청에서 쿠키 전송 단 반드시 secure 속성이 true여야 함
              maxAge: 15 * 60 * 1000, // 15분
            });

            res.cookie("refreshToken", refreshToken, {
              httpOnly: true,
              secure: false, // ture : HTTPS 환경에서만 작동, false : HTTP 환경에서도 작동(로컬 환경)
              sameSite: "strict", // CSRF 방지 -> 이거 사용보다 그냥 CSRF 토큰 사용하는게 더 안전 -> 따라서 적용
              //strict : 같은 사이트에서만 쿠키 전송
              //lax : GET 요청에서만 쿠키 전송
              //none : 모든 요청에서 쿠키 전송 단 반드시 secure 속성이 true여야 함
              maxAge: 7 * 24 * 60 * 60 * 1000, // 7일
            });

            // Step 7: 응답 반환
            res.status(200).json({
              success: true,
              message: "로그인 성공",
              name: user.name,
              userId: user.user_id, // 사용자 ID, 프론트에서 사용
              permissions: user.permission, // 사용자 권한, 프론트에서 사용
            });
          });
      });
    })
    .catch((err) => {
      // 에러 처리
      if (err.status) {
        res.status(err.status).json({
          success: false,
          message: err.message,
        });
      } else {
        console.error("서버 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "서버 오류 발생",
          error: err.message,
        });
      }
    });
});
// *** 로그인 API 끝 ***



// *** 회원가입 API 시작 ***
app.post("/users/register", csrfProtection, limiter, (req: Request, res: Response) => {
  const { name, id, password, email } = req.body as {
    name: string;     // 이름
    id: string;       // 아이디(학번)
    password: string; // 비밀번호
    email: string;    // 이메일
  };

  
  // 입력값 검증
  if (!validator.isLength(name, { min: 2, max: 30 }) || !/^[가-힣a-zA-Z\s]+$/.test(name)) {
    res.status(400).json({ success: false, message: "이름은 2~30자의 한글, 영문 및 공백만 허용됩니다." });
    return;
  }

  if (!validator.isNumeric(id, { no_symbols: true }) || id.length < 7 || id.length > 10) {
    res.status(400).json({ success: false, message: "학번은 숫자로만 구성된 7~10자리 값이어야 합니다." });
    return;
  }

  if (!validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }

  if (
    !validator.isStrongPassword(password, {
      minLength: 8,
      minNumbers: 1,
      minSymbols: 1,
      minUppercase: 1,
    }) || 
    !allowedSymbols.test(password) // 허용된 문자만 포함하지 않은 경우
  ) {
    res.status(400).json({
      success: false,
      message: "비밀번호는 8자리 이상, 영문, 숫자, 그리고 ! @ # $ % ^ & * ? 특수문자만 포함해야 합니다.",
    });
    return;
  }


  // Step 0: 탈퇴된 계정인지 확인
  db.query("SELECT id, state FROM user WHERE id = ?", [id])
    .then((rows: any) => {
      if (rows.length > 0 && rows[0].state === "inactive") {
        // 탈퇴된 계정인 경우
        return Promise.reject({
          status: 400,
          message: "탈퇴된 계정입니다. 계정을 복구해주세요.",
        });
      }

      // Step 1: 학생 정보가 존재하는지 확인
      return db.query("SELECT student_id FROM student WHERE student_id = ? AND name = ?", [id, name]);
    })
    .then((rows: any) => {
      if (rows.length === 0) {
        // 학생 정보가 없는 경우
        return Promise.reject({
          status: 400,
          message: "해당하는 학생이 존재하지 않습니다.",
        });
      }

      // Step 2: 사용자 ID 중복 확인
      return db.query("SELECT id FROM user WHERE id = ? AND state = 'active'", [id]);
    })
    .then((rows: any) => {
      if (rows.length > 0) {
        // 활성 계정이 이미 존재하는 경우
        return Promise.reject({
          status: 400,
          message: "이미 존재하는 학번입니다. 다른 학번을 사용해주세요.",
        });
      }

      // Step 3: 비밀번호 암호화
      return bcrypt.hash(password, 10);
    })
    .then((hashedPassword: string) => {
      // Step 4: 사용자 저장
      return db.query(
        "INSERT INTO user (name, id, password, state, email) VALUES (?, ?, ?, 'active', ?)",
        [name, id, hashedPassword, email]
      );
    })
    .then((result: any) => {
      // Step 5: 성공 응답 반환
      res.status(201).json({
        success: true,
        message: "사용자가 성공적으로 등록되었습니다",
      });
    })
    .catch((err: any) => {
      // Step 6: 에러 처리
      if (err.status) {
        // 사용자 정의 에러 처리
        res.status(err.status).json({
          success: false,
          message: err.message,
        });
      } else {
        console.error("서버 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "서버 오류 발생",
          error: err.message,
        });
      }
    });
});
// *** 회원가입 API 끝 ***



// *** 로그아웃 API 시작 ***
app.post("/users/logout", csrfProtection, (req: Request, res: Response) => {
  const { refreshToken } = req.cookies; // 쿠키에서 Refresh Token 추출

  if (!refreshToken) {
    res.status(400).json({
      success: false,
      message: "Refresh Token이 필요합니다.",
    });
    return;
  }

  db.query("SELECT * FROM user WHERE refreshtoken = ?", [refreshToken])
    .then((rows: any[]) => {
      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "유효하지 않은 Refresh Token입니다.",
        });
      }

      // DB에서 Refresh Token 제거
      return db.query("UPDATE user SET refreshtoken = NULL WHERE refreshtoken = ?", [refreshToken])
        .then(() => {
          // 클라이언트에서 쿠키 삭제
          res.clearCookie("accessToken");
          res.clearCookie("refreshToken");

          return res.status(200).json({
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



// *** 토큰 재발급 API 시작 ***
app.post("/users/token/refresh", csrfProtection, (req: Request, res: Response) => {
  const { refreshToken } = req.cookies; // 쿠키에서 Refresh Token 추출

  if (!refreshToken) {
    res.status(400).json({
      success: false,
      message: "Refresh Token이 필요합니다.",
    });
    return;
  }

  db.query("SELECT * FROM user WHERE refreshtoken = ?", [refreshToken])
    .then((rows: any) => {
      if (rows.length === 0) {
        return res.status(403).json({
          success: false,
          message: "유효하지 않은 Refresh Token입니다.",
        });
      }

      // Refresh Token 유효성 검증 및 Access Token 재발급
      try {
        const decoded: any = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!);
        const newAccessToken = jwt.sign(
          { userId: decoded.userId, name: decoded.name, permission: decoded.permission },
          process.env.JWT_ACCESS_SECRET!,
          { expiresIn: "15m" } // Access Token 만료 시간
        );

        res.cookie("accessToken", newAccessToken, {
          httpOnly: true,
          secure: false, // HTTPS 환경에서 true
          sameSite: "strict",
          maxAge: 15 * 60 * 1000, // 15분
        });

        return res.status(200).json({
          success: true,
          message: "Access Token이 갱신되었습니다.",
        });
      } catch (err) {
        // Refresh Token 만료 시 DB에서 삭제
        db.query("UPDATE user SET refreshtoken = NULL WHERE refreshtoken = ?", [refreshToken]);
        return res.status(403).json({
          success: false,
          message: "Refresh Token이 만료되었습니다.",
        });
      }
    })
    .catch((err) => {
      console.error("Token Refresh 처리 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 토큰 갱신에 실패했습니다.",
      });
    });
});
// *** 토큰 재발급 API 끝 ***



// *** 계정 탈퇴 API 시작 ***
app.patch("/users/account",csrfProtection, limiter,  authenticateToken, (req: Request, res: Response) => {
  const userId = req.user?.userId; // 인증된 사용자 정보에서 userId 추출

  if (!userId) {
    res.status(403).json({
      success: false,
      message: "인증된 사용자가 아닙니다.",
    });
    return;
  }

  // Step 1: 사용자 상태를 inactive로 변경하고 Refresh Token 초기화
  db.query("UPDATE user SET state = 'inactive', refreshtoken = NULL WHERE user_id = ?", [userId])
    .then(() => {
      // Step 2: 클라이언트 쿠키 삭제 (로그아웃 처리)
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");

      // Step 3: 응답 반환
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
app.post("/reservations", csrfProtection, limiter, authenticateToken, async (req: Request, res: Response) => {
  const { userId, seat_id, book_date } = req.body;

  if (!Number.isInteger(seat_id) || seat_id <= 0) {
    res.status(400).json({ success: false, message: "유효하지 않은 좌석 ID입니다." });
    return;
  }

  console.log("변환 전 Booking Date:", book_date);
  const bookDateKST = moment.tz(book_date, "Asia/Seoul").format("YYYY-MM-DD HH:mm:ss");
  console.log("변환된 Booking Date (KST):", bookDateKST);
  
  let connection;
  try {
    connection = await db.getConnection(); // 데이터베이스 연결
    await connection.beginTransaction(); // 트랜잭션 시작

    // Step 1: 사용자가 이미 예약한 상태인지 확인
    const existingReservation = await connection.query(
      "SELECT * FROM book WHERE user_id = ? AND state = 'book'",
      [userId]
    );
    
    if (existingReservation.length > 0) {
      throw { status: 400, message: "예약한 좌석이 존재합니다. 퇴실 후 다시 예약해주세요." };
    }

    // Step 2: 좌석 존재 확인
    const seat = await connection.query("SELECT * FROM seat WHERE seat_id = ?", [seat_id]);

    if (seat.length === 0) {
      throw { status: 400, message: "존재하지 않는 좌석입니다." };
    }

    // Step 3: 좌석 예약 상태 확인
    const existingBooking = await connection.query(
      "SELECT * FROM book WHERE seat_id = ? AND state = 'book'",
      [seat_id]
    );

    if (existingBooking.length > 0) {
      throw { status: 400, message: "이미 예약된 좌석입니다." };
    }

    // Step 4: 예약 생성
    const result = await connection.query(
      "INSERT INTO book (user_id, seat_id, book_date, state) VALUES (?, ?, ?, 'book')",
      [userId, seat_id, bookDateKST]
    );

    // 예약 로그 기록
    await connection.query(
      `
      INSERT INTO logs (book_id, log_date, type, log_type) VALUES (?, NOW(), 'book', 'book')
      `,
      [result.insertId]
    );

    // Step 5: 트랜잭션 커밋
    await connection.commit();

    res.status(201).json({
      success: true,
      reservation_id: result.insertId,
      message: "예약이 성공적으로 완료되었습니다.",
    });
  } catch (err) {
    if (connection) await connection.rollback(); // 에러 발생 시 트랜잭션 롤백
    res.status(err.status || 500).json({
      success: false,
      message: err.message || "예약 처리 중 서버 오류가 발생했습니다.",
    });
  } finally {
    if (connection) connection.release(); // 연결 해제
  }
});
// *** 좌석 예약 생성 API 끝 ***



// 좌석 퇴실 API 시작
app.delete("/reservations", csrfProtection, limiter, authenticateToken, async (req: Request, res: Response) => {
  const { userId } = req.user; // 인증된 사용자 정보에서 userId 추출

  let connection: any;

  try {
    // Step 1: 데이터베이스 연결 및 트랜잭션 시작
    connection = await db.getConnection();
    await connection.beginTransaction();

    // Step 2: 사용자 예약 상태 확인
    const rows = await connection.query("SELECT * FROM book WHERE user_id = ? AND state = 'book'", [userId]);
    if (rows.length === 0) {
      res.status(400).json({
        success: false,
        message: "현재 예약된 좌석이 없습니다.",
      });
      return;
    }

    // Step 3: 예약 상태를 'end'로 업데이트
    await connection.query("UPDATE book SET state = 'end' WHERE user_id = ? AND state = 'book'", [userId]);

    const bookId = rows[0].book_id; // 예약 ID 추출
    // 로그 기록
    await connection.query(
      `
      INSERT INTO logs (book_id, log_date, type, log_type) VALUES (?, NOW(), 'end', 'book')
      `,
      [bookId]
    );

    // Step 4: 트랜잭션 커밋
    await connection.commit();

    res.status(200).json({
      success: true,
      message: "좌석 퇴실 처리가 완료되었습니다.",
    });
  } catch (err) {
    // Step 5: 에러 발생 시 롤백
    if (connection) await connection.rollback();

    console.error("좌석 퇴실 처리 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "좌석 퇴실 처리 중 서버 오류가 발생했습니다.",
    });
  } finally {
    // Step 6: 연결 해제
    if (connection) connection.release();
  }
});
// 좌석 퇴실 API 끝



// 좌석 데이터 제공 API 시작
app.get("/seats", limiter, authenticateToken, async (req, res) => {
  try {
    const rows = await db.query(`
      SELECT 
        seat_id,
        name AS seat_name,
        type,
        pc_surpport,
        image_path,
        basic_manners,
        warning,
        (SELECT state FROM book WHERE seat.seat_id = book.seat_id AND book.state = 'book' LIMIT 1) AS state
      FROM seat
    `);

    res.status(200).json({
      success: true,
      seats: rows, // 좌석 데이터 반환
    });
  } catch (err) {
    console.error("좌석 데이터를 가져오는 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "좌석 데이터를 불러오는 데 실패했습니다.",
    });
  }
});
// 좌석 데이터 제공 API 끝



// 이메일 인증 코드 전송 API 시작
app.post("/users/verify-email", csrfProtection, async (req: Request, res: Response) => {
  const { email, id, purpose, name = "" } = req.body; // 요청에 id 추가, name은 선택적

  if (!email || !id) {
    res.status(400).json({ success: false, message: "학번과 이메일 주소가 필요합니다." });
    return;
  }
  if (!validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }

  if (!validator.isNumeric(id, { no_symbols: true }) || id.length < 7 || id.length > 10) {
    res.status(400).json({ success: false, message: "학번은 숫자로만 구성된 7~10자리 값이어야 합니다." });
    return;
  }

  let connection;
  try {
    connection = await db.getConnection();
    await connection.beginTransaction(); // 트랜잭션 시작

    switch (purpose) {
      case "resetPassword":
        const resetRows = await connection.query("SELECT id, email, state FROM user WHERE id = ? AND email = ?", [id, email]);
        const resetUser = resetRows[0];

        if (!resetUser) {
          res.status(404).json({ success: false, message: "학번과 이메일이 일치하는 계정이 없습니다." });
          return;
        }

        if (resetUser.state === "inactive") {
          res.status(400).json({ success: false, message: "탈퇴된 계정입니다. 계정을 복구해주세요." });
          return;
        }
        break;

      case "verifyAccount":
        const studentRows = await connection.query("SELECT student_id FROM student WHERE student_id = ? AND name = ?", [id, name]);
        const student = studentRows[0];

        if (!student) {
          res.status(400).json({
            success: false,
            message: "해당 학번과 이름에 맞는 학생 정보를 찾을 수 없습니다. 관리자에게 문의하세요.",
          });
          return;
        }

        const existingUserRows = await connection.query("SELECT id, email, state FROM user WHERE id = ? OR email = ?", [id, email]);
        const existingUser = existingUserRows[0];

        if (existingUser) {
          if (existingUser.id === id) {
            res.status(400).json({ success: false, message: "이미 존재하는 학번입니다. 다른 학번을 사용해주세요." });
            return;
          }

          if (existingUser.email === email) {
            if (existingUser.state === "inactive") {
              res.status(400).json({ success: false, message: "탈퇴된 계정입니다. 계정을 복구해주세요." });
              return;
            }

            res.status(400).json({ success: false, message: "이미 존재하는 이메일입니다. 다른 이메일을 사용해주세요." });
            return;
          }
        }
        break;

      case "accountRecovery":
        const recoveryRows = await connection.query("SELECT id, email, state FROM user WHERE id = ? AND email = ?", [id, email]);
        const recoveryUser = recoveryRows[0];

        if (!recoveryUser) {
          res.status(404).json({ success: false, message: "학번과 이메일이 일치하는 계정이 없습니다." });
          return;
        }

        if (recoveryUser.state !== "inactive") {
          res.status(400).json({ success: false, message: "이미 활성화된 계정입니다." });
          return;
        }
        break;

      case "modifyInfo":
        const modifyRows = await connection.query("SELECT id, email FROM user WHERE id = ?", [id]);
        const modifyUser = modifyRows[0];

        if (!modifyUser) {
          res.status(404).json({ success: false, message: "해당 학번과 일치하는 계정을 찾을 수 없습니다." });
          return;
        }

        if (modifyUser.email === email) {
          res.status(400).json({ success: false, message: "현재 이메일과 동일한 값입니다. 변경할 이메일을 입력해주세요." });
          return;
        }
        break;

      default:
        res.status(400).json({ success: false, message: "잘못된 요청입니다." });
        return;
    }

    // Step 1: 랜덤 인증 코드 생성
    const generateRandomCode = (n: number): string => {
      let str = "";
      for (let i = 0; i < n; i++) {
        str += Math.floor(Math.random() * 10);
      }
      return str;
    };
    const verificationCode = generateRandomCode(6);

    // Step 2: 인증 코드 저장 (유효 기간 5분)
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5분 후
    await connection.query(
      "INSERT INTO email_verification (email, verification_code, expires_at) VALUES (?, ?, ?)",
      [email, verificationCode, expiresAt]
    );

    // Step 3: 이메일 전송
    const transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.NODEMAILER_USER,
        pass: process.env.NODEMAILER_PASS,
      },
    });

    const mailOptions = {
      from: `"FabLab 예약 시스템" <${process.env.NODEMAILER_USER}>`,
      to: email,
      subject: "[FabLab 예약 시스템] 인증번호를 입력해주세요.",
      html: `
        <h1>이메일 인증</h1>
        <div>
          <h2>인증번호 [<b>${verificationCode}</b>]를 인증 창에 입력하세요.</h2><br/>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    await connection.commit(); // 트랜잭션 커밋
    res.status(200).json({
      success: true,
      message: "인증번호가 이메일로 발송되었습니다.",
    });
  } catch (err) {
    if (connection) await connection.rollback(); // 트랜잭션 롤백
    console.error("Error sending email verification code:", err);
    res.status(500).json({ success: false, message: "메일 발송에 실패했습니다." });
  } finally {
    if (connection) connection.release();
  }
});
// 이메일 인증 코드 전송 API 끝



// 인증번호 검증 API 시작
app.post("/users/verify-code", csrfProtection, async (req: Request, res: Response) => {
  const { email, code } = req.body;

  if (!email) {
    res.status(400).json({ success: false, message: "이메일을 입력해주세요." });
    return;
  }
  if (!code) {
    res.status(400).json({ success: false, message: "인증번호를 입력해주세요." });
    return;
  }
  if (!validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }
  if (!validator.isNumeric(code, { no_symbols: true }) || code.length !== 6) {
    res.status(400).json({ success: false, message: "인증 코드는 6자리 숫자입니다." });
    return;
  }

  try {
    // 인증 코드 검증
    const [record] = await db.query(
      "SELECT verification_code, expires_at FROM email_verification WHERE email = ? ORDER BY created_at DESC LIMIT 1",
      [email]
    );

    if (!record) {
      res.status(400).json({ success: false, message: "인증번호가 존재하지 않습니다." });
      return;
    }

    const { verification_code: storedCode, expires_at: expiresAt } = record;

    if (new Date() > new Date(expiresAt)) {
      res.status(400).json({ success: false, message: "인증번호가 만료되었습니다." });
      return;
    }

    if (storedCode !== code) {
      res.status(400).json({ success: false, message: "인증번호가 일치하지 않습니다." });
      return;
    }

    // 인증 성공
    await db.query("DELETE FROM email_verification WHERE email = ?", [email]); // 검증 후 데이터 삭제

    res.status(200).json({ success: true, message: "인증번호가 확인되었습니다." });
  } catch (err) {
    console.error("Error verifying code:", err);
    res.status(500).json({ success: false, message: "서버 오류가 발생했습니다." });
  }
});
 // 인증번호 검증 API 끝



 // 비밀번호 찾기 API 시작
 app.patch("/users/password/reset", csrfProtection, (req: Request, res: Response) => {
  const { id, email, password } = req.body;

  if (!id || !email || !password) {
    res.status(400).json({
      success: false,
      message: "학번, 이메일, 비밀번호는 필수 입력 항목입니다.",
    });
    return;
  }

  if (!validator.isNumeric(id, { no_symbols: true }) || id.length < 7 || id.length > 10) {
    res.status(400).json({ success: false, message: "학번은 숫자로만 구성된 7~10자리 값이어야 합니다." });
    return;
  }

  if (!validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }

  // if (
  //   !validator.isStrongPassword(password, {
  //     minLength: 8,
  //     minNumbers: 1,
  //     minSymbols: 1,
  //     minUppercase: 1,
  //   }) || 
  //   !allowedSymbols.test(password) // 허용된 문자만 포함하지 않은 경우
  // ) {
  //   res.status(400).json({
  //     success: false,
  //     message: "비밀번호는 8자리 이상, 영문, 숫자, 그리고 ! @ # $ % ^ & * ? 특수문자만 포함해야 합니다.",
  //   });
  //   return;
  // }


  // Step 1: 사용자 조회
  db.query("SELECT * FROM user WHERE id = ? AND email = ?", [id, email])
    .then((rows: any[]) => {
      if (rows.length === 0) {
        return Promise.reject({
          status: 404,
          message: "일치하는 사용자를 찾을 수 없습니다.",
        });
      }

      // Step 2: 비밀번호 암호화
      return bcrypt.hash(password, 10)
      .then((hashedPassword) => {
        return db.query("UPDATE user SET password = ? WHERE id = ?", [hashedPassword, id]);
      });
    })
    .then(() => {
      res.status(200).json({
        success: true,
        message: "비밀번호가 성공적으로 변경되었습니다.",
      });
    })
    .catch((err) => {
      if (err.status) {
        res.status(err.status).json({ success: false, message: err.message });
      } else {
        console.error("비밀번호 변경 중 서버 오류:", err);
        res.status(500).json({
          success: false,
          message: "비밀번호 변경 중 서버 오류가 발생했습니다.",
        });
      }
    });
});
// 비밀번호 찾기 API 끝



// 계정 복구 API 시작
app.patch("/users/account/recovery", csrfProtection, (req: Request, res: Response) => {
  const { id, email } = req.body;

  if (!id || !email) {
    res.status(400).json({
      success: false,
      message: "학번과 이메일을 모두 입력해주세요.",
    });
    return;
  }
  if (!validator.isNumeric(id, { no_symbols: true }) || id.length < 7 || id.length > 10) {
    res.status(400).json({ success: false, message: "학번은 숫자로만 구성된 7~10자리 값이어야 합니다." });
    return;
  }

  if (!validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }

  // Step 1: 학번과 이메일이 일치하는 계정 확인
  db.query("SELECT * FROM user WHERE id = ? AND email = ?", [id, email])
    .then((rows: any[]) => {
      const user = rows[0];

      if (!user) {
        res.status(404).json({
          success: false,
          message: "학번과 이메일이 일치하는 계정을 찾을 수 없습니다.",
        });
        return Promise.reject(); // 이후 실행 방지
      }

      if (user.state === "active") {
        res.status(400).json({
          success: false,
          message: "이미 활성화된 계정입니다.",
        });
        return Promise.reject(); // 이후 실행 방지
      }

      // Step 2: 계정 상태 복구
      return db.query("UPDATE user SET state = 'active' WHERE id = ? AND email = ?", [id, email]);
    })
    .then(() => {
      res.status(200).json({
        success: true,
        message: "계정이 성공적으로 복구되었습니다.",
      });
    })
    .catch((err) => {
      if (err) {
        console.error("계정 복구 처리 중 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "서버 오류로 인해 계정 복구에 실패했습니다.",
        });
      }
    });
});
// 계정 복구 API 끝



// 사용자 정보 제공 API 시작
app.get("/users/info", csrfProtection, limiter, authenticateToken, (req: Request, res: Response) => {
  const userId = req.user?.userId; // 인증된 사용자 정보에서 userId 추출

  if (!userId) {
    res.status(403).json({
      success: false,
      message: "인증된 사용자가 아닙니다.",
    });
    return;
  }

  // DB에서 사용자 정보 조회
  db.query("SELECT id, name, email, permission FROM user WHERE user_id = ?", [userId])
    .then((rows: any[]) => {
      if (rows.length === 0) {
        res.status(404).json({
          success: false,
          message: "사용자 정보를 찾을 수 없습니다.",
        });
        return;
      }

      // 사용자 정보 반환
      const user = rows[0];
      res.status(200).json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          permission: user.permission,
        },
      });
    })
    .catch((err) => {
      console.error("사용자 정보 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "사용자 정보 조회 중 서버 오류가 발생했습니다.",
      });
    });
});
// 사용자 정보 제공 API 끝



// 사용자 정보 수정 API 시작
app.patch("/users/modify", csrfProtection, limiter, authenticateToken, (req: Request, res: Response) => {
  const { name, email, password, newpassword, isVerified } = req.body;
  const userId = req.user?.userId; // 인증된 사용자 ID

  if (!userId || !name || !email) {
    res.status(400).json({
      success: false,
      message: "필수 정보가 누락되었습니다.",
    });
    return;
  }
  if (!validator.isLength(name, { min: 2, max: 30 }) || !/^[가-힣a-zA-Z\s]+$/.test(name)) {
    res.status(400).json({ success: false, message: "이름은 2~30자의 한글, 영문 및 공백만 허용됩니다." });
    return;
  }
  if (!validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }
  // if (
  //   !validator.isStrongPassword(password, {
  //     minLength: 8,
  //     minNumbers: 1,
  //     minSymbols: 1,
  //     minUppercase: 1,
  //   }) || 
  //   !allowedSymbols.test(password) // 허용된 문자만 포함하지 않은 경우
  // ) {
  //   res.status(400).json({
  //     success: false,
  //     message: "비밀번호는 8자리 이상, 영문, 숫자, 그리고 ! @ # $ % ^ & * ? 특수문자만 포함해야 합니다.",
  //   });
  //   return;
  // }
  // if (
  //   !validator.isStrongPassword(newpassword, {
  //     minLength: 8,
  //     minNumbers: 1,
  //     minSymbols: 1,
  //     minUppercase: 1,
  //   }) || 
  //   !allowedSymbols.test(newpassword) // 허용된 문자만 포함하지 않은 경우
  // ) {
  //   res.status(400).json({
  //     success: false,
  //     message: "비밀번호는 8자리 이상, 영문, 숫자, 그리고 ! @ # $ % ^ & * ? 특수문자만 포함해야 합니다.",
  //   });
  //   return;
  // }
  if (password === newpassword) {
    res.status(400).json({
      success: false,
      message: "새 비밀번호는 이전 비밀번호와 동일할 수 없습니다.",
    });
    return;
  }

  // Step 1: 사용자 정보 조회
  db.query("SELECT email, password FROM user WHERE user_id = ?", [userId])
    .then((rows: any[]) => {
      if (rows.length === 0) {
        return Promise.reject({
          status: 404,
          message: "사용자 정보를 찾을 수 없습니다.",
        });
      }

      const user = rows[0];

      // Step 2: 이메일 변경 검증
      if (email !== user.email && !isVerified) {
        return Promise.reject({
          status: 400,
          message: "이메일 변경 시 인증이 필요합니다.",
        });
      }

      // Step 3: 비밀번호 변경 검증
      if (newpassword) {
        return bcrypt.compare(password, user.password).then((isPasswordMatch) => {
          if (!isPasswordMatch) {
            return Promise.reject({
              status: 400,
              message: "현재 비밀번호가 일치하지 않습니다.",
            });
          }

          // 비밀번호 해싱
          return bcrypt.hash(newpassword, 10).then((hashedPassword) => {
            return db.query("UPDATE user SET password = ? WHERE user_id = ?", [hashedPassword, userId]);
          });
        });
      }
      return Promise.resolve();
    })
    .then(() => {
      // Step 4: 이메일 및 이름 변경
      if (email || name) {
        return db.query("UPDATE user SET email = ?, name = ? WHERE user_id = ?", [email, name, userId]);
      }
      return Promise.resolve();
    })
    .then(() => {
      res.status(200).json({
        success: true,
        message: "사용자 정보가 성공적으로 수정되었습니다.",
      });
    })
    .catch((err) => {
      if (err.status) {
        res.status(err.status).json({
          success: false,
          message: err.message,
        });
      } else {
        console.error("사용자 정보 수정 중 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "사용자 정보 수정 중 서버 오류가 발생했습니다.",
        });
      }
    });
});
// 사용자 정보 수정 API 끝


// 예약 정보 조회 API 시작
app.get("/users/reservations", csrfProtection, limiter, authenticateToken, (req: Request, res: Response) => {
  const userId = req.user?.userId; // 인증된 사용자 ID
  
  if (!userId) {
    res.status(403).json({ success: false, message: "사용자가 인증되지 않았습니다." });
    return;
  }

  db.query(
    `
    SELECT 
        b.book_id,
        DATE_FORMAT(b.book_date, '%Y/%m/%d %H:%i') AS book_date,
        b.state,
        s.name AS seat_name,
        l.type AS log_type,
        l.log_date,
        r.reason AS cancel_reason
    FROM 
        book b
    LEFT JOIN 
        seat s ON b.seat_id = s.seat_id
    LEFT JOIN 
        logs l ON b.book_id = l.book_id AND l.log_type = 'book' AND l.type = 'cancel'
    LEFT JOIN 
        book_restriction r ON b.book_id = r.book_id
    WHERE 
        b.user_id = ?
    ORDER BY 
        b.book_date DESC
    `,
    [userId]
  )
  .then((rows: any[]) => {
    res.status(200).json({ success: true, reservations: rows });
  })
  .catch((err: any) => {
    console.error("예약 정보 조회 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "서버 오류로 인해 예약 정보를 가져오지 못했습니다.",
    });
  });
});
// 예약 정보 조회 API 끝


// 공지사항 목록 조회 API 시작
app.get("/notice", limiter, (req: Request, res: Response) => {
  const query = `
    SELECT 
      notice_id, 
      title, 
      DATE_FORMAT(date, '%Y/%m/%d') AS formatted_date, 
      views 
    FROM notice 
    ORDER BY date DESC`;

  db.query(query)
    .then((rows) => {
      res.status(200).json({
        success: true,
        notices: rows.map((row) => ({
          notice_id: row.notice_id,
          title: row.title,
          date: row.formatted_date,
          views: row.views,
        })),
      });
    })
    .catch((err) => {
      console.error("공지사항 데이터 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "공지사항 데이터를 가져오는 중 오류가 발생했습니다.",
      });
    });
});
// 공지사항 목록 조회 API 끝


// 공지사항 내용 조회 API 시작
app.get("/notice/:id", async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const query = `
      SELECT 
        n.notice_id, 
        n.title, 
        n.content, 
        n.date, 
        u.name AS author_name, 
        n.views
      FROM notice n
      LEFT JOIN user u ON n.admin_id = u.user_id
      WHERE n.notice_id = ?
    `;

    const [notice] = await db.query(query, [id]);

    if (!notice) {
      res.status(404).json({ message: "공지사항을 찾을 수 없습니다." });
      return;
    }

    res.json({ notice });
  } catch (err) {
    console.error("공지사항 조회 중 오류 발생:", err);
    res.status(500).json({ message: "공지사항 데이터를 가져오는 중 오류가 발생했습니다." });
  }
});
// 공지사항 내용 조회 API 끝


// 공지사항 조회수 증가 API 시작
app.patch("/notice/:id/increment-views", csrfProtection, limiter, async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    // 조회수 증가 트랜잭션 시작
    const connection = await db.getConnection();
    await connection.beginTransaction();

    // 조회수 증가
    const result = await connection.query(
      "UPDATE notice SET views = views + 1 WHERE notice_id = ?",
      [id]
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      res.status(404).json({ message: "공지사항을 찾을 수 없습니다." });
      return;
    }

    // 트랜잭션 커밋
    await connection.commit();
    connection.release();

    res.status(200).json({ message: "조회수가 증가했습니다." });
  } catch (err) {
    console.error("조회수 증가 처리 중 오류 발생:", err);
    res.status(500).json({ message: "조회수 증가 처리 중 오류가 발생했습니다." });
  }
});
// 공지사항 조회수 증가 API 끝




