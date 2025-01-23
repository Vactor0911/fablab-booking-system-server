// 어드민 관련 API

import express from "express";
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate";
import { db } from "./index.ts";
import RateLimit from "express-rate-limit";
import csurf from "csurf";
import validator from "validator"; // 유효성 검사 라이브러리
import nodemailer from "nodemailer";  // 이메일 전송 라이브러리
import he from "he";  // HTML 인코딩 라이브러리
import bcrypt from "bcrypt";  // 비밀번호 해싱 라이브러리
const allowedSymbols = /^[a-zA-Z0-9!@#$%^&*?]*$/; // 허용된 문자만 포함하는지 확인

// Rate Limit 설정
const limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 요청 횟수
});

const router = express.Router();

// CSRF 보호 설정
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: false, // HTTPS 환경에서는 true로 설정
    sameSite: "strict", // CSRF 보호를 위한 설정
  },
});

// 모든 좌석과 예약 정보 조회 (관리자 전용) - 이미 route가 /admin이므로 /admin/seats로 설정하지 않아도 됨
router.get("/seats", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const rows = await db.query(
      `SELECT 
        s.seat_id, 
        s.name AS seat_name, 
        b.user_id, 
        u.id AS user_student_id, -- 학번 추가
        u.name AS user_name, 
        b.state 
      FROM seat s
      LEFT JOIN book b ON s.seat_id = b.seat_id AND b.state = 'book'
      LEFT JOIN user u ON b.user_id = u.user_id
      `
    );

    res.status(200).json({
      success: true,
      seats: rows,
    });
  } catch (err) {
    console.error("좌석 정보 조회 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "좌석 정보를 불러오는 중 서버 오류가 발생했습니다.",
    });
  }
});


// 특정 좌석 정보 조회 API 시작
// 해당 API 는 관리자만 접근 가능하며, 특정 좌석의 정보와 예약 정보를 함께 조회합니다.
router.get("/seats/:seatName", limiter, authenticateToken, authorizeAdmin, async (req, res) => {
  const { seatName } = req.params;

  try {
    // 좌석 정보와 예약 정보를 조인하여 가져오기
    const [seat] = await db.query(
      `
      SELECT 
        s.seat_id,
        s.name AS seat_name,
        s.type,
        s.pc_surpport,
        s.image_path,
        s.basic_manners,
        s.warning,
        DATE_FORMAT(b.book_date, '%Y-%m-%d') AS reservation_date,
        TIME_FORMAT(b.book_date, '%H:%i') AS reservation_time,
        u.id AS user_student_id,
        u.name AS user_name
      FROM seat s
      LEFT JOIN book b ON s.seat_id = b.seat_id AND b.state = 'book'
      LEFT JOIN user u ON b.user_id = u.user_id
      WHERE s.name = ?
      `,
      [seatName]
    );

    if (!seat) {
      res.status(404).json({
        success: false,
        message: "해당 좌석 정보를 찾을 수 없습니다.",
      });
      return;
    }

    // API 응답
    res.status(200).json({
      success: true,
      seat: {
        seatId: seat.seat_id,
        seatName: seat.seat_name,
        reservationDate: seat.reservation_date || "예약 없음",
        reservationTime: seat.reservation_time || "예약 없음",
        userStudentId: seat.user_student_id || "없음",
        userName: seat.user_name || "없음",
        basicManners: seat.basic_manners,
        warning: seat.warning,
        imagePath: seat.image_path || "/placeholder.jpg", // 기본 이미지 경로
      },
    });
  } catch (err) {
    console.error("좌석 정보 조회 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "좌석 정보를 조회하는 중 오류가 발생했습니다.",
    });
  }
});
// 특정 좌석 정보 조회 API 끝


// 강제 퇴실 API 시작
router.post("/force-exit", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
    const { seatId, reason, userId } = req.body;

    if (!seatId || !reason) {
       res.status(400).json({
        success: false,
        message: "좌석 ID와 퇴실 사유는 필수 항목입니다.",
      });
      return;
    }
    // 특수문자 검증 (허용되지 않는 특수문자 체크)
    if (!validator.isLength(reason, { max: 100 }) || /[`<>]/.test(reason)) {
      res.status(400).json({
        success: false,
        message: "퇴실 사유는 최대 100자의 텍스트이며, <, >, ` 문자는 허용되지 않습니다.",
      });
      return;
    }

    let connection: any;
    try {
      connection = await db.getConnection(); // 트랜잭션 시작
      await connection.beginTransaction();

      // 예약 정보 가져오기
      const [reservation] = await connection.query(
        `SELECT b.book_id, b.user_id, u.email, u.name, s.name AS seat_name 
         FROM book b
         LEFT JOIN user u ON b.user_id = u.user_id
         LEFT JOIN seat s ON b.seat_id = s.seat_id
         WHERE b.seat_id = ? AND b.state = 'book'`,
        [seatId]
      );

      if (!reservation) {
        res.status(404).json({
          success: false,
          message: "해당 좌석에 활성화된 예약이 없습니다.",
        });
        return;
      }

      const { book_id, email, name, seat_name } = reservation;

      // 예약 상태를 'cancel'로 업데이트
      await connection.query(
        `
        UPDATE book 
        SET state = 'cancel' 
        WHERE book_id = ? AND state = 'book'
        `,
        [book_id]
      );

      // 예약 로그 기록
      await connection.query(
        `
        INSERT INTO logs (book_id, log_date, type, log_type, reason, admin_id) VALUES (?, NOW(), 'cancel', 'book', ?, ?)
        `,
        [book_id, reason, userId]
      );

      // 이메일 전송
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
        subject: `[FabLab 예약 시스템] ${seat_name} 강제 퇴실 알림`,
        html: `
          <h1>강제 퇴실 알림</h1>
          <p>${name}님,</p>
          <p>다음 좌석에 대한 예약이 관리자에 의해 강제 퇴실 처리되었습니다.</p>
          <ul>
            <li><strong>좌석 번호:</strong> ${seat_name}</li>
            <li><strong>퇴실 사유:</strong> ${he.encode(reason)}</li>
          </ul>
          <p>문의사항이 있으시면 관리자에게 문의하세요.</p>
        `,
      };

      try {
        await transporter.sendMail(mailOptions);
      } catch (emailError) {
        console.error("이메일 전송 중 오류 발생:", emailError);
      }

      // 트랜잭션 커밋
      await connection.commit();

      res.status(200).json({
        success: true,
        message: "강제 퇴실 처리가 완료되었으며, 이메일이 전송되었습니다.",
      });
    } catch (err) {
      if (connection) await connection.rollback(); // 에러 발생 시 롤백
      console.error("강제 퇴실 처리 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "강제 퇴실 처리 중 서버 오류가 발생했습니다.",
      });
    }
  }
);
// 강제 퇴실 API 끝



// 공지사항 수정 API 시작
router.patch("/notice/:id", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => { 
  const { id } = req.params;
  const { title, content, userId } = req.body;
  const noticeId = parseInt(id, 10);

  if (isNaN(noticeId)) {
    res.status(400).json({
      success: false,
      message: "유효하지 않은 공지사항 ID입니다.",
    });
    return;
  }

  if (!title || !content) {
    res.status(400).json({
      success: false,
      message: "제목과 내용을 모두 입력해주세요.",
    });
    return;
  }

  if (!validator.isLength(title, { min: 1, max: 100 })) {
    res.status(400).json({
      success: false,
      message: "제목은 1~100자 사이여야 합니다.",
    });
    return;
  }

  if (!validator.isLength(content, { min: 1, max: 1000 })) {
    res.status(400).json({
      success: false,
      message: "내용은 1~1000자 사이여야 합니다.",
    });
    return;
  }

  let connection: any;
  try {
    connection = await db.getConnection();
    await connection.beginTransaction();

    // 공지사항 수정 쿼리
    await connection.query(
      `
      UPDATE notice
      SET title = ?, content = ?, admin_id = ?, date = NOW()
      WHERE notice_id = ?
      `,
      [title.trim(), content.trim(), userId, noticeId] // 인코딩 제거
    );

    // 로그 기록 추가
    await connection.query(
      `
      INSERT INTO logs (notice_id, log_date, type, log_type, admin_id) VALUES (?, NOW(), 'edit', 'notice', ?)
      `,
      [noticeId, userId]
    );

    await connection.commit();

    res.status(200).json({
      success: true,
      message: "공지사항이 성공적으로 수정되었습니다.",
    });
    return;
  } catch (err) {
    console.error("공지사항 수정 중 오류 발생:", err);
    if (connection) await connection.rollback();
    res.status(500).json({
      success: false,
      message: "공지사항 수정 중 서버 오류가 발생했습니다.",
    });
  } finally {
    if (connection) connection.release(); // 연결 해제 추가
  }
});
// 공지사항 수정 API 끝


// 공지사항 생성, 작성 API 시작
router.post("/notice", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
  const { title, content, userId } = req.body;

  if (!title || !content) {
    res.status(400).json({
      success: false,
      message: "제목과 내용을 모두 입력해주세요.",
    });
    return;
  }

  if (!validator.isLength(title, { min: 1, max: 100 })) {
    res.status(400).json({
      success: false,
      message: "제목은 1~100자 사이여야 합니다.",
    });
    return;
  }

  if (!validator.isLength(content, { min: 1, max: 1000 })) {
    res.status(400).json({
      success: false,
      message: "내용은 1~1000자 사이여야 합니다.",
    });
    return;
  }
  let connection: any;
  try {
    connection = await db.getConnection();
    await connection.beginTransaction();

    // 공지사항 생성 쿼리
    const result = await connection.query(
      `
      INSERT INTO notice (title, content, admin_id, date)
      VALUES (?, ?, ?, NOW())
      `,
      [title.trim(), content.trim(), userId] // 인코딩 제거
    );

    const noticeId = result.insertId; // 생성된 공지사항 ID 가져오기

    // 로그 기록 추가
    await connection.query(
      `
      INSERT INTO logs (notice_id, log_date, type, log_type, admin_id) VALUES (?, NOW(), 'create', 'notice', ?)
      `,
      [noticeId, userId]
    );

    await connection.commit();

    res.status(201).json({
      success: true,
      message: "공지사항이 성공적으로 생성되었습니다.",
      noticeId,
    });
    return;
  } catch (err) {
    console.error("공지사항 생성 중 오류 발생:", err);
    if (connection) await connection.rollback();
    res.status(500).json({
      success: false,
      message: "공지사항 생성 중 서버 오류가 발생했습니다.",
    });
  } finally {
    if (connection) connection.release(); // 연결 해제 추가
  }
});
// 공지사항 생성 API 끝


// 공지사항 삭제 API 시작
router.delete("/notice/:id", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const noticeId = parseInt(id, 10);
  const { userId } = req.body;

  if (isNaN(noticeId)) {
    res.status(400).json({
      success: false,
      message: "유효하지 않은 공지사항 ID입니다.",
    });
    return;
  }

  let connection: any;

  try {
    // DB 연결 및 트랜잭션 시작
    connection = await db.getConnection();
    await connection.beginTransaction();

    // 공지사항 존재 여부 확인
    const [notice] = await connection.query(
      `SELECT * FROM notice WHERE notice_id = ?`,
      [noticeId]
    );

    if (!notice || notice.length === 0) {
      res.status(404).json({
        success: false,
        message: "해당 공지사항을 찾을 수 없습니다.",
      });
      return;
    }

    // 삭제 로그 기록
    await connection.query(
      `
      INSERT INTO logs (notice_id, log_date, type, log_type, admin_id) VALUES (?, NOW(), 'delete', 'notice', ?)
      `,
      [noticeId, userId]
    );

    // 공지사항 삭제
    await connection.query(
      `DELETE FROM notice WHERE notice_id = ?`,
      [noticeId]
    );

    // 트랜잭션 커밋
    await connection.commit();

    res.status(200).json({
      success: true,
      message: "공지사항이 성공적으로 삭제되었습니다.",
    });
    return;
  } catch (err) {
    if (connection) await connection.rollback(); // 에러 발생 시 롤백
    console.error("공지사항 삭제 중 오류 발생:", err);
    res.status(500).json({
      success: false,
      message: "공지사항 삭제 중 서버 오류가 발생했습니다.",
    });
    return;
  } finally {
    if (connection) connection.release(); // DB 연결 해제
  }
});
// 공지사항 삭제 API 끝

// 모든 로그 조회 API 시작
router.get("/logs/all", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice'
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE
          l.book_id = b.book_id
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("모든 로그 조회 중 오류 발생:", err);

      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 모든 로그 조회 API 끝


// 예약 로그 조회 API 시작
router.get("/logs/book", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice'
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE 
          l.type = 'book' -- 예약 로그만 조회
          AND b.book_id = l.book_id
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 예약 로그 조회 API 끝


// 퇴실 로그 조회 API 시작
router.get("/logs/end", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice'
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE 
          l.type = 'end' -- 퇴실 로그만 조회
          AND b.book_id = l.book_id
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 퇴실 로그 조회 API 끝


// 강제 퇴실 로그 조회 API 시작
router.get("/logs/cancel", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice'
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE 
          l.type = 'cancel' -- 강제 퇴실 로그만 조회
          AND b.book_id = l.book_id
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 강제 퇴실 로그 조회 API 끝


// 공지사항 작성 로그 조회 API 시작
router.get("/logs/create", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice' AND n.admin_id = l.admin_id
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE 
          l.type = 'create' -- 공지사항 작성 로그만 조회
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 공지사항 작성 로그 조회 API 끝


// 공지사항 수정 로그 조회 API 시작
router.get("/logs/edit", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice' AND n.admin_id = l.admin_id
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE 
          l.type = 'edit' -- 공지사항 수정 로그만 조회
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 공지사항 수정 로그 조회 API 끝

// 공지사항 삭제 로그 조회 API 시작
router.get("/logs/delete", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          l.log_id,
          l.type AS log_action, -- 로그 액션 (create, edit, delete, book, cancel, end 등)
          l.log_type,           -- 로그 유형 (book, notice)
          DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
          u.name AS user_name,
          u.id AS user_info,
          s.name AS seat_name,
          l.reason AS restriction_reason,
          a.name AS admin_name
        FROM 
          logs l
        LEFT JOIN 
          book b ON l.book_id = b.book_id AND l.log_type = 'book'
        LEFT JOIN 
          notice n ON l.notice_id = n.notice_id AND l.log_type = 'notice' AND n.admin_id = l.admin_id
        LEFT JOIN 
          user u ON b.user_id = u.user_id
        LEFT JOIN 
          seat s ON b.seat_id = s.seat_id
        LEFT JOIN 
          user a ON l.admin_id = a.user_id
        WHERE 
          l.type = 'delete' -- 공지사항 삭제 로그만 조회
        ORDER BY 
          l.log_date DESC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((logs) => {
      // logs가 배열이 아닐 경우 변환
      if (!Array.isArray(logs)) {
        logs = Object.values(logs);
      }

      if (logs.length === 0) {
        res.status(404).json({
          success: false,
          message: "로그 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        logs: logs,
      });
    })
    .catch((err) => {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 로그 데이터를 가져올 수 없습니다.",
      });
    });
});
// 공지사항 삭제 로그 조회 API 끝


// 사용자 목록 조회 API 시작
router.get("/users", csrfProtection, limiter, authenticateToken, authorizeAdmin, (req, res) => {
  db.getConnection()
    .then((connection) => {
      return connection.query(
        `
        SELECT 
          u.user_id,
          u.name,
          u.id,
          u.email,
          u.permission,
          u.state,
          DATE_FORMAT(MAX(b.book_date), '%Y-%m-%d %H:%i') AS last_reservation -- 마지막 예약 일시를 가져오기 위해 MAX 사용
        FROM 
          user u
        LEFT JOIN 
          book b ON u.user_id = b.user_id
        GROUP BY 
          u.user_id, u.name, u.id, u.email, u.permission, u.state
        ORDER BY 
          u.permission ASC, u.state ASC, u.name ASC
        `
      ).finally(() => connection.release()); // 연결 해제 추가
    })
    .then((users) => {
      // users가 배열이 아닐 경우 변환
      if (!Array.isArray(users)) {
        users = Object.values(users);
      }

      if (users.length === 0) {
        res.status(404).json({
          success: false,
          message: "사용자 데이터가 없습니다.",
        });
        return;
      }

      res.status(200).json({
        success: true,
        users: users,
      });
    })
    .catch((err) => {
      console.error("사용자 목록 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 사용자 데이터를 가져올 수 없습니다.",
      });
    });
});
// 사용자 목록 조회 API 끝


// 사용자 정보 수정 API 시작
router.patch("/users/:user_id", csrfProtection, limiter, authenticateToken, authorizeAdmin, async (req, res) => {
  const { user_id } = req.params;
  const { name, email, permission, state, newPassword } = req.body;
  const userId = parseInt(user_id, 10);

  if (isNaN(userId)) {
    res.status(400).json({
      success: false,
      message: "유효하지 않은 사용자 ID입니다.",
    });
    return;
  }

  // 이름 입력값 검증
  if (name && (!validator.isLength(name, { min: 2, max: 30 }) || !/^[가-힣a-zA-Z\s]+$/.test(name))) {
    res.status(400).json({ success: false, message: "이름은 2~30자의 한글, 영문 및 공백만 허용됩니다." });
    return;
  }

  // 이메일 입력값 검증
  if (email && !validator.isEmail(email)) {
    res.status(400).json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
    return;
  }

  // 비밀번호 입력값 검증
  if (newPassword && (
    !validator.isStrongPassword(newPassword, {
      minLength: 8,
      minNumbers: 1,
      minSymbols: 1,
      minUppercase: 0,
    }) ||
    !allowedSymbols.test(newPassword)
  )) {
    res.status(400).json({
      success: false,
      message: "비밀번호는 8자리 이상, 영문, 숫자, 그리고 ! @ # $ % ^ & * ? 특수문자만 포함해야 합니다.",
    });
    return;
  }

  let connection;
  try {
    connection = await db.getConnection();
    await connection.beginTransaction();

    // 요청자의 권한 확인
    const requestingUser = req.user; // 요청자의 정보
    const [targetUserResult] = await connection.query(
      `SELECT permission FROM user WHERE user_id = ?`,
      [userId]
    );

    if (!targetUserResult) {
      res.status(404).json({
        success: false,
        message: "대상이 되는 사용자를 찾을 수 없습니다.",
      });
      return;
    }

    const targetPermission = targetUserResult.permission;

    // 권한 제한: admin은 admin 및 superadmin 계정을 수정할 수 없음
    if (
      requestingUser.permission === "admin" &&
      (targetPermission === "admin" || targetPermission === "superadmin")
    ) {
      res.status(403).json({
        success: false,
        message: "해당 사용자를 수정할 권한이 없습니다.",
      });
      return;
    }

    const fieldsToUpdate: string[] = [];
    const queryParams: (string | number)[] = [];

    // 이름 수정 (admin, superadmin 모두 가능)
    if (name) {
      fieldsToUpdate.push("name = ?");
      queryParams.push(name.trim());
    }

    // 이메일 수정 (admin, superadmin 모두 가능)
    if (email) {
      fieldsToUpdate.push("email = ?");
      queryParams.push(email.trim());
    }

    // 상태(state) 수정 (admin, superadmin 모두 가능)
    if (state) {
      fieldsToUpdate.push("state = ?");
      queryParams.push(state);
    }

    // 권한(permission) 수정 (superadmin만 가능)
    if (requestingUser.permission === "superadmin" && permission) {
      fieldsToUpdate.push("permission = ?");
      queryParams.push(permission);
    }

    // 필수 항목이 하나도 없는 경우 업데이트 쿼리 실행하지 않음
    if (fieldsToUpdate.length > 0) {
      const updateQuery = `
      UPDATE user
      SET ${fieldsToUpdate.join(", ")}
      WHERE user_id = ?`;
      queryParams.push(userId);
      await connection.query(updateQuery, queryParams);
    }

    // 비밀번호 변경 (admin, superadmin 모두 가능)
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await connection.query(
        `
        UPDATE user
        SET password = ?
        WHERE user_id = ?`,
        [hashedPassword, userId]
      );
    }

    await connection.commit();

    res.status(200).json({
      success: true,
      message: "사용자 정보가 성공적으로 수정되었습니다.",
    });
  } catch (err) {
    console.error("사용자 정보 수정 중 오류 발생:", err);
    if (connection) await connection.rollback();
    res.status(500).json({
      success: false,
      message: "사용자 정보 수정 중 서버 오류가 발생했습니다.",
    });
  } finally {
    if (connection) connection.release();
  }
});
// 사용자 정보 수정 API 끝







export default router;
