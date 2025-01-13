import express, { Request, Response, NextFunction } from "express";
import MariaDB from "mariadb";
import cors from "cors";
import dotenv from "dotenv"; // 환경 변수 사용한 민감한 정보 관리
import bcrypt from "bcrypt"; // 비밀번호 암호화 최신버전
import jwt from "jsonwebtoken";

import cookieParser from "cookie-parser"; // 쿠키 파싱 미들웨어 추가
import adminRoutes from "./admin"; // 관리자 전용 API
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate"; // 인증 미들웨어

import nodemailer from "nodemailer";  // 이메일 전송 라이브러리

// .env 파일 로드
dotenv.config();
// 환경변수가 하나라도 없으면 서버 실행 불가
["DB_HOST", "DB_PORT", "DB_USERNAME", "DB_PASSWORD", "DB_DATABASE", "JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET"].forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`해당 환경변수가 존재하지 않습니다.: ${key}`);
  }
});

const PORT = 3010; // 서버가 실행될 포트 번호
const FRONT_PORT = 4000; // 프론트 서버 포트 번호

const app = express();
app.use(cors({ origin: `http://localhost:${FRONT_PORT}`, credentials: true })); // CORS 설정, credentials는 프론트와 백엔드의 쿠키 공유를 위해 필요
app.use(express.json()); // JSON 요청을 처리하기 위한 미들웨어
app.use(cookieParser()); // 쿠키 파싱 미들웨어 등록

// MariaDB 연결
export const db = MariaDB.createPool({
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

// *** 사용자 로그인 API 시작 ***
app.post("/users/login", (req: Request, res: Response) => {
  const { id, password } = req.body;

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
          { userId: user.user_id },
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
              sameSite: "strict", // CSRF 방지
              maxAge: 15 * 60 * 1000, // 15분
            });

            res.cookie("refreshToken", refreshToken, {
              httpOnly: true,
              secure: false, // ture : HTTPS 환경에서만 작동, false : HTTP 환경에서도 작동(로컬 환경)
              sameSite: "strict", // CSRF 방지
              maxAge: 7 * 24 * 60 * 60 * 1000, // 7일
            });

            // Step 7: 응답 반환
            res.status(200).json({
              success: true,
              message: "로그인 성공",
              name: user.name,
              userId: user.user_id, // 사용자 ID, 프론트에서 사용
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
// *** 사용자 로그인 API 끝 ***



// *** 사용자 회원가입 API 시작 ***
app.post("/users/register", (req: Request, res: Response) => {
  const { name, id, password, email } = req.body as {
    name: string;     // 이름
    id: string;       // 아이디(학번)
    password: string; // 비밀번호
    email: string;    // 이메일
  };

  // // 비밀번호 조건 검증
  // const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
  // if (!passwordRegex.test(password)) {
  //   res.status(400).json({
  //     success: false,
  //     message: "비밀번호는 영문 대소문자, 숫자, 특수문자가 포함된 8자리 이상의 문자열이어야 합니다.",
  //   });
  //   return;
  // }

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
// *** 사용자 회원가입 API 끝 ***


// *** 로그아웃 API 시작 ***
app.post("/users/logout", (req: Request, res: Response) => {
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
app.post("/users/token/refresh", (req: Request, res: Response) => {
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
          { userId: decoded.userId },
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
app.patch("/users/account", authenticateToken, (req: Request, res: Response) => {
  const userId = req.user?.userId; // 인증된 사용자 정보에서 userId 추출

  if (!userId) {
    res.status(401).json({
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

// 좌석 예약 상태 확인 API 시작
app.get("/reservations", authenticateToken, (req: Request, res: Response) => {
  db.query("SELECT seat_id FROM book WHERE state = 'book'")
    .then((rows: any) => {
      res.status(200).json(rows);
    })
    .catch((err) => {
      console.error("예약 상태를 가져오는 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 예약 상태를 가져오지 못했습니다.",
      });
    });
});
// 좌석 예약 상태 확인 API 끝


// *** 좌석 예약 생성 API 시작 ***
app.post("/reservations", authenticateToken, (req: Request, res: Response) => {
  const { userId, seat_id, book_date } = req.body;

  // Step 1: 좌석 존재 확인
  db.query("SELECT * FROM seat WHERE seat_id = ?", [seat_id])
    .then((rows: any) => {
      if (rows.length === 0) {
        return Promise.reject({
          status: 400,
          message: "존재하지 않는 좌석입니다.",
        });
      }

      // Step 2: 좌석 예약 상태 확인
      return db.query(
        "SELECT * FROM book WHERE seat_id = ? AND state = 'book'",
        [seat_id]
      );
    })
    .then((rows: any) => {
      if (rows.length > 0) {
        return Promise.reject({
          status: 400,
          message: "이미 예약된 좌석입니다.",
        });
      }

      // Step 3: 예약 생성
      return db.query(
        "INSERT INTO book (user_id, seat_id, book_date, state) VALUES (?, ?, ?, 'book')",
        [userId, seat_id, book_date]
      );
    })
    .then((result: any) => {
      res.status(201).json({
        success: true,
        reservation_id: result.insertId, // 생성된 예약 ID 반환
        message: "예약이 성공적으로 완료되었습니다.",
      });
    })
    .catch((err) => {
      if (err.status) {
        res.status(err.status).json({
          success: false,
          message: err.message,
        });
      } else {
        console.error("예약 생성 중 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "예약 생성 중 서버 오류가 발생했습니다.",
        });
      }
    });
});
// *** 좌석 예약 생성 API 끝 ***

// 좌석 데이터 제공 API 시작
app.get("/seats", authenticateToken, (req: Request, res: Response) => {
  db.query("SELECT * FROM seat")
    .then((rows: any) => {
      res.status(200).json({
        success: true,
        seats: rows, // 좌석 데이터 반환
      });
    })
    .catch((err) => {
      console.error("좌석 데이터를 가져오는 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "좌석 데이터를 불러오는 데 실패했습니다.",
      });
    });
});
// 좌석 데이터 제공 API 끝


// 이메일 인증 코드 전송 API 시작
app.post("/users/verify-email", async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    res.status(400).json({ success: false, message: "이메일 주소가 필요합니다." });
    return;
  }

  try {
    // Step 0: 이메일 상태 확인
    const [existingUser] = await db.query("SELECT email, state FROM user WHERE email = ?", [email]);

    if (existingUser) {
      if (existingUser.state === "inactive") {
        res.status(400).json({ success: false, message: "탈퇴된 계정입니다. 계정을 복구해주세요." });
        return;
      }
      res.status(400).json({ success: false, message: "이미 존재하는 이메일입니다. 다른 이메일을 사용해주세요." });
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
    await db.query(
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

    res.status(200).json({
      success: true,
      message: "인증번호가 이메일로 발송되었습니다.",
    });
  } catch (err) {
    console.error("Error sending email verification code:", err);
    res.status(500).json({ success: false, message: "메일 발송에 실패했습니다." });
  }
});
 // 이메일 인증 코드 전송 API 끝


// 인증번호 검증 API 시작
app.post("/users/verify-code", async (req: Request, res: Response) => {
  const { email, code } = req.body;

  if (!email) {
    res.status(400).json({ success: false, message: "이메일을 입력해주세요." });
    return;
  }
  if (!code) {
    res.status(400).json({ success: false, message: "인증번호를 입력해주세요." });
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




