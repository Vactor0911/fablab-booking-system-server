// 어드민 관련 API

import express, { Request, Express } from "express";
import { authenticateToken, authorizeAdmin } from "./middleware/authenticate";
import { db, initializeForceExitScheduler } from "./index.ts";
import RateLimit from "express-rate-limit";
import csurf from "csurf";
import validator from "validator"; // 유효성 검사 라이브러리
import nodemailer from "nodemailer"; // 이메일 전송 라이브러리
import he from "he"; // HTML 인코딩 라이브러리
import bcrypt from "bcrypt"; // 비밀번호 해싱 라이브러리

import multer from "multer"; // 파일 업로드 라이브러리
import path from "path"; // 경로 라이브러리
import fs from "fs"; // 파일 시스템 라이브러리
import sanitizeHtml from "sanitize-html"; // HTML 필터링 라이브러리

// 허용할 태그 및 속성 정의
const sanitizeOptions = {
  allowedTags: [
    "p",
    "span",
    "b",
    "i",
    "strong",
    "em",
    "ul",
    "ol",
    "li",
    "a",
    "br",
    "blockquote",
    "s",
  ], // 허용할 태그
  allowedAttributes: {
    "*": ["style", "class"],
    a: ["href", "target"],
  },
  // allowedFrameHostnames: ['www.youtube.com'] // iframe 허용하되 유튜브 사이트만 허용
};

const allowedSymbolsForPassword = /^[a-zA-Z0-9!@#$%^&*?]*$/; // 허용된 문자들
const allowedSymbolsForNotice = /[`]/; // 금지된 문자 (백틱(`)만 제한)
const allowedSymbols = /[`'<>-]/; // 금지된 문자

// Rate Limit 설정
const limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 1000, // 요청 횟수
  validate: { xForwardedForHeader: false },
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

// 이미지 파일 업로드를 위한 Multer 설정 시작

// Multer 설정
const uploadDir = path.join(__dirname, "../fablab-booking-system-server/image"); // 이미지 업로드 경로, __dirname은 현재 파일의 경로 예) E:
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true }); // 폴더 없으면 생성
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // 업로드 경로 설정
  },

  filename: async (req, file, cb) => {
    try {
      const filePath = path.join(uploadDir, file.originalname);

      // 동일한 파일이 존재하는지 확인
      if (fs.existsSync(filePath)) {
        req.existingImagePath = `/image/${file.originalname}`; // 기존 파일 경로 저장
        return cb(null, file.originalname); // 기존 파일 이름 그대로 사용
      }

      // 새 파일일 경우 고유 이름 생성
      const uniqueName = `${file.originalname}`;
      req.existingImagePath = `/image/${uniqueName}`; // 새 파일 경로 저장
      cb(null, uniqueName);
    } catch (err) {
      console.error("파일 처리 중 오류 발생:", err);
      cb(err, null);
    }
  },
});

const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = ["image/jpeg", "image/png", "image/gif"];
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error("지원되지 않는 파일 형식입니다. (JPEG, PNG, GIF만 허용)"),
      false
    );
  }
};

const upload = multer({ storage, fileFilter });

// 이미지 파일 업로드를 위한 Multer 설정 끝

// ----------------- API 라우트 -----------------

// 모든 좌석과 예약 정보 조회 (관리자 전용) - 이미 route가 /admin이므로 /admin/seats로 설정하지 않아도 됨
router.get(
  "/seats",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
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
  }
);

// 특정 좌석 정보 조회 API 시작
// 해당 API 는 관리자만 접근 가능하며, 특정 좌석의 정보와 예약 정보를 함께 조회합니다.
router.get(
  "/seats/:seatName",
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { seatName } = req.params;

    try {
      // 좌석 정보와 예약 정보를 조인하여 가져오기
      const [seat] = await db.query(
        `
      SELECT 
        s.seat_id,
        s.name AS seat_name,
        s.pc_support,
        s.image_path,
        s.warning,
        DATE_FORMAT(b.book_date, '%Y-%m-%d') AS reservation_date,
        TIME_FORMAT(b.book_date, '%H:%i') AS reservation_time,
        u.id AS user_student_id,
        u.name AS user_name,
        ds.basic_manners,
        ds.available_end_time
      FROM seat s
      LEFT JOIN book b ON s.seat_id = b.seat_id AND b.state = 'book'
      LEFT JOIN user u ON b.user_id = u.user_id
      CROSS JOIN default_settings ds
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

      // 이미지 파일 읽기 및 Base64 인코딩
      let imageBase64 = ""; // 이미지 Base64 데이터
      const absoluteImagePath = path.join(
        uploadDir,
        path.basename(seat.image_path || "")
      );

      if (fs.existsSync(absoluteImagePath)) {
        const imageBuffer = fs.readFileSync(absoluteImagePath); // 이미지 파일 읽기
        imageBase64 = `data:image/png;base64,${imageBuffer.toString("base64")}`; // Base64 변환
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
          availableEndTime: seat.available_end_time, // 예약 종료 시간 추가
          warning: seat.warning,
          image: imageBase64, // 이미지 데이터를 포함
          pc_support: seat.pc_support,
        },
      });
    } catch (err) {
      console.error("좌석 정보 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "좌석 정보를 조회하는 중 오류가 발생했습니다.",
      });
    }
  }
);
// 특정 좌석 정보 조회 API 끝

// 강제 퇴실 API 시작
router.post(
  "/force-exit",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { seatName, reason, userId } = req.body;

    if (!seatName) {
      res.status(400).json({
        success: false,
        message: "좌석 이름은 필수 항목입니다.",
      });
      return;
    }

    // 기본 퇴실 사유 설정
    const exitReason =
      reason &&
      validator.isLength(reason, { max: 100 }) &&
      !allowedSymbols.test(reason)
        ? reason
        : "관리자에 의해 강제 퇴실되었습니다.";

    let connection: any;
    try {
      connection = await db.getConnection(); // 트랜잭션 시작
      await connection.beginTransaction();

      // Step 1: 좌석 정보 조회
      const [seat] = await connection.query(
        `SELECT seat_id FROM seat WHERE name = ?`,
        [seatName]
      );

      if (!seat) {
        res.status(404).json({
          success: false,
          message: "해당 좌석을 찾을 수 없습니다.",
        });
        return;
      }

      const seatId = seat.seat_id;

      // Step 2: 예약 정보 가져오기
      const [reservation] = await connection.query(
        `SELECT b.book_id, b.user_id, u.email, u.name 
       FROM book b
       LEFT JOIN user u ON b.user_id = u.user_id
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

      const { book_id, email, name } = reservation;

      // Step 3: 예약 상태를 'cancel'로 업데이트
      await connection.query(
        `UPDATE book SET state = 'cancel' WHERE book_id = ? AND state = 'book'`,
        [book_id]
      );

      // Step 4: 예약 로그 기록
      await connection.query(
        `INSERT INTO logs (book_id, log_date, type, log_type, reason, admin_id) VALUES (?, NOW(), 'cancel', 'book', ?, ?)`,
        [book_id, exitReason, userId]
      );

      // Step 5: 이메일 전송
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
        subject: `[FabLab 예약 시스템] ${seatName} 강제 퇴실 알림`,
        html: `
        <h1>강제 퇴실 알림</h1>
        <p>${name}님,</p>
        <p>다음 좌석에 대한 예약이 관리자에 의해 강제 퇴실 처리되었습니다.</p>
        <ul>
          <li><strong>좌석 번호:</strong> ${he.encode(seatName)}</li>
          <li><strong>퇴실 사유:</strong> ${he.encode(exitReason)}</li>
        </ul>
        <p>문의사항이 있으시면 관리자에게 문의하세요.</p>
      `,
      };

      try {
        await transporter.sendMail(mailOptions);
      } catch (emailError) {
        console.error("이메일 전송 중 오류 발생:", emailError);
      }

      // Step 6: 트랜잭션 커밋
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
    } finally {
      if (connection) connection.release(); // DB 연결 해제
    }
  }
);
// 강제 퇴실 API 끝

// 공지사항 수정 API 시작
router.patch(
  "/notice/:uuid",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { noticeId, title, content, userId } = req.body;

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

    if (
      allowedSymbolsForNotice.test(title) ||
      allowedSymbolsForNotice.test(content)
    ) {
      res.status(400).json({
        success: false,
        message: "제목과 내용에 허용되지 않는 특수문자가 포함되어 있습니다.",
      });
      return;
    }

    // **XSS 공격 방지를 위해 HTML 정리**
    const sanitizedContent = sanitizeHtml(content, sanitizeOptions);
    const sanitizedTitle = sanitizeHtml(title, sanitizeOptions);

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
        [sanitizedTitle, sanitizedContent, userId, noticeId]
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
  }
);
// 공지사항 수정 API 끝

// 공지사항 생성, 공지사항 작성 API 시작
router.post(
  "/notice",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
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
    if (
      allowedSymbolsForNotice.test(title) ||
      allowedSymbolsForNotice.test(content)
    ) {
      res.status(400).json({
        success: false,
        message: "제목과 내용에 허용되지 않는 특수문자가 포함되어 있습니다.",
      });
      return;
    }

    // **XSS 공격 방지를 위해 HTML 정리**
    const sanitizedContent = sanitizeHtml(content, sanitizeOptions);
    const sanitizedTitle = sanitizeHtml(title, sanitizeOptions);

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
        [sanitizedTitle, sanitizedContent, userId] // 인코딩 제거
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
  }
);
// 공지사항 생성 API 끝

// 공지사항 삭제 API 시작
router.delete(
  "/notice/:id",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { userId, noticeId } = req.body;

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
      await connection.query(`DELETE FROM notice WHERE notice_id = ?`, [
        noticeId,
      ]);

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
  }
);
// 공지사항 삭제 API 끝

// 모든 로그 조회 API (검색 필터 포함)
router.get(
  "/logs/all",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%"; // 검색어 처리

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 로그 개수 조회 (검색 필터 포함)
      const totalLogs = await connection.query(
        `
      SELECT COUNT(*) AS totalLogs
      FROM logs l
      LEFT JOIN book b ON l.book_id = b.book_id
      LEFT JOIN notice n ON l.notice_id = n.notice_id
      LEFT JOIN user u ON b.user_id = u.user_id
      LEFT JOIN seat s ON b.seat_id = s.seat_id
      LEFT JOIN user a ON l.admin_id = a.user_id
      WHERE u.id LIKE ? OR u.name LIKE ? OR a.id LIKE ? OR a.name LIKE ?
      `,
        [search, search, search, search]
      );

      if (totalLogs[0].totalLogs === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalLogs: 0,
          logs: [],
        });
        return;
      }

      // 로그 데이터 조회 (검색 필터 및 페이징 적용)
      const logs = await connection.query(
        `
      SELECT 
        l.log_id, l.type AS log_action, l.log_type, DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
        u.name AS user_name, u.id AS user_id, s.name AS seat_name, l.reason AS restriction_reason, a.name AS admin_name, a.id AS admin_id
      FROM logs l
      LEFT JOIN book b ON l.book_id = b.book_id
      LEFT JOIN notice n ON l.notice_id = n.notice_id
      LEFT JOIN user u ON b.user_id = u.user_id
      LEFT JOIN seat s ON b.seat_id = s.seat_id
      LEFT JOIN user a ON l.admin_id = a.user_id
      WHERE u.id LIKE ? OR u.name LIKE ? OR a.id LIKE ? OR a.name LIKE ?
      ORDER BY l.log_date DESC
      LIMIT ? OFFSET ?;
      `,
        [search, search, search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalLogs: totalLogs[0].totalLogs.toString(),
        logs,
      });
    } catch (err) {
      console.error("모든 로그 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "서버 오류 발생" });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 모든 로그 조회 API 끝

// 예약 로그 조회 API (검색 필터 포함 book)
router.get(
  "/logs/book",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 예약 로그 개수 조회
      const totalLogs = await connection.query(
        `SELECT COUNT(*) AS totalLogs
        FROM logs l
       LEFT JOIN book b ON l.book_id = b.book_id
       LEFT JOIN user u ON b.user_id = u.user_id
       LEFT JOIN seat s ON b.seat_id = s.seat_id
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'book' AND l.type = 'book' 
       AND (u.name LIKE ? OR u.id LIKE ? OR a.id LIKE ? OR a.name LIKE ?)
      `,
        [search, search, search, search]
      );

      if (totalLogs[0].totalLogs === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalLogs: 0,
          logs: [],
        });
        return;
      }

      // 예약 로그 조회 (검색 필터 및 페이징 적용)
      const logs = await connection.query(
        `SELECT l.log_id, l.type AS log_action, l.log_type, DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
              u.name AS user_name, u.id AS user_id, s.name AS seat_name, l.reason AS restriction_reason, a.name AS admin_name, a.id AS admin_id
       FROM logs l
       LEFT JOIN book b ON l.book_id = b.book_id
       LEFT JOIN user u ON b.user_id = u.user_id
       LEFT JOIN seat s ON b.seat_id = s.seat_id
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'book' AND l.type = 'book' 
       AND (u.name LIKE ? OR u.id LIKE ? OR a.id LIKE ? OR a.name LIKE ?)
       ORDER BY l.log_date DESC
       LIMIT ? OFFSET ?;
      `,
        [search, search, search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalLogs: totalLogs[0].totalLogs.toString(),
        logs,
      });
    } catch (err) {
      console.error("예약 로그 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "서버 오류 발생" });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 예약 로그 조회 API 끝

//  퇴실 로그 조회 API (검색 필터 포함 end)
router.get(
  "/logs/end",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 퇴실 로그 개수 조회
      const totalLogs = await connection.query(
        `SELECT COUNT(*) AS totalLogs
        FROM logs l
       LEFT JOIN book b ON l.book_id = b.book_id
       LEFT JOIN user u ON b.user_id = u.user_id
       LEFT JOIN seat s ON b.seat_id = s.seat_id
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'book' AND l.type = 'end' 
       AND (u.name LIKE ? OR u.id LIKE ? OR a.id LIKE ? OR a.name LIKE ?)
      `,
        [search, search, search, search]
      );

      if (totalLogs[0].totalLogs === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalLogs: 0,
          logs: [],
        });
        return;
      }

      // 퇴실 로그 조회 (검색 필터 및 페이징 적용)
      const logs = await connection.query(
        `SELECT l.log_id, l.type AS log_action, l.log_type, DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
              u.name AS user_name, u.id AS user_id, s.name AS seat_name, l.reason AS restriction_reason, a.name AS admin_name, a.id AS admin_id
       FROM logs l
       LEFT JOIN book b ON l.book_id = b.book_id
       LEFT JOIN user u ON b.user_id = u.user_id
       LEFT JOIN seat s ON b.seat_id = s.seat_id
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'book' AND l.type = 'end' 
       AND (u.name LIKE ? OR u.id LIKE ? OR a.id LIKE ? OR a.name LIKE ?)
       ORDER BY l.log_date DESC
       LIMIT ? OFFSET ?;
      `,
        [search, search, search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalLogs: totalLogs[0].totalLogs.toString(),
        logs,
      });
    } catch (err) {
      console.error("퇴실 로그 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "서버 오류 발생" });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 퇴실 로그 조회 API 끝

//  강제 퇴실 로그 조회 API (검색 필터 포함 cancel)
router.get(
  "/logs/cancel",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 강제 퇴실 로그 개수 조회
      const totalLogs = await connection.query(
        `SELECT COUNT(*) AS totalLogs
        FROM logs l
       LEFT JOIN book b ON l.book_id = b.book_id
       LEFT JOIN user u ON b.user_id = u.user_id
       LEFT JOIN seat s ON b.seat_id = s.seat_id
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'book' AND l.type = 'cancel'
       AND (u.name LIKE ? OR u.id LIKE ? OR a.id LIKE ? OR a.name LIKE ?)
      `,
        [search, search, search, search]
      );

      if (totalLogs[0].totalLogs === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalLogs: 0,
          logs: [],
        });
        return;
      }

      // 강제 퇴실 로그 조회 (검색 필터 및 페이징 적용)
      const logs = await connection.query(
        `SELECT l.log_id, l.type AS log_action, l.log_type, DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
              u.name AS user_name, u.id AS user_id, s.name AS seat_name, l.reason AS restriction_reason, a.name AS admin_name, a.id AS admin_id
       FROM logs l
       LEFT JOIN book b ON l.book_id = b.book_id
       LEFT JOIN user u ON b.user_id = u.user_id
       LEFT JOIN seat s ON b.seat_id = s.seat_id
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'book' AND l.type = 'cancel'
       AND (u.name LIKE ? OR u.id LIKE ? OR a.id LIKE ? OR a.name LIKE ?)
       ORDER BY l.log_date DESC
       LIMIT ? OFFSET ?;
      `,
        [search, search, search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalLogs: totalLogs[0].totalLogs.toString(),
        logs,
      });
    } catch (err) {
      console.error("강제 퇴실 로그 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "서버 오류 발생" });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 강제 퇴실 로그 조회 API 끝

// 공지사항 로그 조회 API (검색 필터 포함 'notice')
router.get(
  "/logs/notice/all",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 공지사항 로그 개수 조회 (검색 필터 적용)
      const totalLogs = await connection.query(
        `SELECT COUNT(*) AS totalLogs
        FROM logs l
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'notice'
       AND (a.id LIKE ? OR a.name LIKE ?)
      `,
        [search, search]
      );

      if (totalLogs[0].totalLogs === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalLogs: 0,
          logs: [],
        });
        return;
      }

      // 공지사항 로그 데이터 조회 (검색 필터 및 페이징 적용)
      const logs = await connection.query(
        `SELECT l.log_id, l.type AS log_action, l.log_type, DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
              a.id AS admin_id, a.name AS admin_name, l.reason AS restriction_reason
       FROM logs l
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'notice'
       AND (a.id LIKE ? OR a.name LIKE ?)
       ORDER BY l.log_date DESC
       LIMIT ? OFFSET ?;
      `,
        [search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalLogs: totalLogs[0].totalLogs.toString(),
        logs,
      });
    } catch (err) {
      console.error("공지사항 로그 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "서버 오류 발생" });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 공지사항 작성 로그 조회 API 끝

//  예약 제한 로그 조회 API (검색 필터 포함 'restriction')
router.get(
  "/logs/book_restriction/all",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 예약 제한 로그 개수 조회 (검색 필터 적용)
      const totalLogs = await connection.query(
        `SELECT COUNT(*) AS totalLogs
        FROM logs l
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'restriction'
       AND (a.id LIKE ? OR a.name LIKE ?)
      `,
        [search, search]
      );

      if (totalLogs[0].totalLogs === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalLogs: 0,
          logs: [],
        });
        return;
      }

      // 예약 제한 로그 데이터 조회 (검색 필터 및 페이징 적용)
      const logs = await connection.query(
        `SELECT l.log_id, l.type AS log_action, l.log_type, DATE_FORMAT(l.log_date, '%Y-%m-%d %H:%i') AS log_date,
              a.id AS admin_id, a.name AS admin_name, l.reason AS restriction_reason
       FROM logs l
       LEFT JOIN user a ON l.admin_id = a.user_id
       WHERE l.log_type = 'restriction'
       AND (a.id LIKE ? OR a.name LIKE ?)
       ORDER BY l.log_date DESC
       LIMIT ? OFFSET ?;
      `,
        [search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalLogs: totalLogs[0].totalLogs.toString(),
        logs,
      });
    } catch (err) {
      console.error("예약 제한 로그 조회 중 오류 발생:", err);
      res.status(500).json({ success: false, message: "서버 오류 발생" });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 예약제한 로그 조회 API 끝

// 사용자 목록 조회 API 시작
router.get(
  "/users",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1; // 기본값 1페이지
    const limit = 10; // 페이지당 10개
    const offset = (page - 1) * limit;
    const search = req.query.search ? `%${req.query.search}%` : "%%"; // 검색어 처리 (LIKE 검색)

    let connection;
    try {
      connection = await db.getConnection();

      // 전체 사용자 수 조회 (검색어 적용)
      const totalUsersResult = await connection.query(
        `
      SELECT COUNT(*) AS totalUsers FROM user;
      `
      );
      const totalUsers = totalUsersResult[0]?.totalUsers || 0;

      if (totalUsers === 0) {
        res.status(200).json({
          success: true,
          totalPages: 0,
          currentPage: page,
          totalUsers: 0,
          users: [],
        });
        return;
      }

      // 전체 관리자 수 조회 (검색어 적용)
      const totalAdminsResult = await connection.query(
        `
      SELECT COUNT(*) AS totalAdmins FROM user
      WHERE permission = 'admin' OR permission = 'superadmin';
      `
      );
      const totalAdmins = totalAdminsResult[0]?.totalAdmins || 0;

      // 사용자 수 조회 (검색 적용)
      const usersCountResult = await connection.query(
        `
      SELECT 
        COUNT(*) AS usersCount
      FROM 
        user u
      WHERE 
        u.name LIKE ? OR u.id LIKE ? -- 검색 필터
      `,
        [search, search]
      );
      const usersCount = usersCountResult[0]?.usersCount || 0;

      // 사용자 목록 조회 (검색 + 페이징 적용)
      const users = await connection.query(
        `
      SELECT 
        u.user_id,
        u.name,
        u.id,
        u.email,
        u.permission,
        u.state,
        DATE_FORMAT(MAX(b.book_date), '%Y-%m-%d %H:%i') AS last_reservation
      FROM 
        user u
      LEFT JOIN 
        book b ON u.user_id = b.user_id
      WHERE 
        u.name LIKE ? OR u.id LIKE ? -- 검색 필터
      GROUP BY 
        u.user_id, u.name, u.id, u.email, u.permission, u.state
      ORDER BY 
        u.user_id DESC -- 최신 사용자 기준 정렬
      LIMIT ? OFFSET ?;
      `,
        [search, search, limit, offset]
      );

      res.status(200).json({
        success: true,
        currentPage: page,
        totalUsers,
        totalAdmins,
        users,
        usersCount,
      });
    } catch (err) {
      console.error("사용자 목록 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "서버 오류로 인해 사용자 데이터를 가져올 수 없습니다.",
      });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 사용자 목록 조회 API 끝

// 사용자 정보 수정 API 시작
router.patch(
  "/users/:user_id",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
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
    if (
      name &&
      (!validator.isLength(name, { min: 2, max: 30 }) ||
        !/^[가-힣a-zA-Z\s]+$/.test(name))
    ) {
      res.status(400).json({
        success: false,
        message: "이름은 2~30자의 한글, 영문 및 공백만 허용됩니다.",
      });
      return;
    }

    // 이메일 입력값 검증
    if (email && !validator.isEmail(email)) {
      res
        .status(400)
        .json({ success: false, message: "유효한 이메일 주소를 입력하세요." });
      return;
    }

    // 비밀번호 입력값 검증
    if (
      newPassword &&
      (!validator.isStrongPassword(newPassword, {
        minLength: 8,
        minNumbers: 1,
        minSymbols: 1,
        minUppercase: 0,
      }) ||
        !allowedSymbolsForPassword.test(newPassword))
    ) {
      res.status(400).json({
        success: false,
        message:
          "비밀번호는 8자리 이상, 영문, 숫자, 특수문자를 포함해야 합니다.",
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
        `SELECT permission, state FROM user WHERE user_id = ?`,
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

      // 사용자 상태(state) 수정 (admin, superadmin 모두 가능)
      const targetCurrentState = targetUserResult.state;

      // 비활성화 시 현재 예약 확인 및 강제 퇴실
      if (state === "inactive" && targetCurrentState !== "inactive") {
        // 현재 예약 확인
        const reservations = await connection.query(
          `SELECT book_id FROM book WHERE user_id = ? AND state = 'book'`,
          [userId]
        );

        if (reservations.length > 0) {
          // 강제 퇴실 처리
          for (const reservation of reservations) {
            await connection.query(
              `UPDATE book SET state = 'cancel' WHERE book_id = ? AND state = 'book'`,
              [reservation.book_id]
            );

            // 로그 기록
            await connection.query(
              `INSERT INTO logs (book_id, log_date, type, log_type, reason) 
              VALUES (?, NOW(), 'cancel', 'book', '사용자 비활성화로 인한 강제 퇴실')`,
              [reservation.book_id]
            );
          }
        }

        // 상태 변경
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
  }
);
// 사용자 정보 수정 API 끝

// 예약 제한 목록 조회 API (검색 필터 추가)
router.get(
  "/book/restriction",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const page = parseInt(req.query.page as string) || 1; // 현재 페이지 (기본값: 1)
    const limit = 10; // 한 페이지에 10개씩 표시
    const offset = (page - 1) * limit;

    // 검색 필터 적용
    const search = req.query.search ? `%${req.query.search}%` : "%%";

    try {
      const query = `
      SELECT 
          br.restriction_uuid,
          br.notice_id,
          n.title AS notice_title,
          a.id AS admin_id,
          a.name AS admin_name,
          br.seat_names,
          DATE_FORMAT(br.restriction_start_date, '%Y-%m-%d %H:%i') AS restriction_start_date,
          DATE_FORMAT(br.restriction_end_date, '%Y-%m-%d %H:%i') AS restriction_end_date
      FROM 
          book_restriction br
      LEFT JOIN 
          notice n ON br.notice_id = n.notice_id
      LEFT JOIN 
          user a ON br.admin_id = a.user_id
      WHERE 
          br.restriction_end_date >= NOW()
          AND (n.title COLLATE utf8mb4_unicode_ci LIKE ?
            OR a.id COLLATE utf8mb4_unicode_ci LIKE ?
            OR a.name COLLATE utf8mb4_unicode_ci LIKE ?)
      ORDER BY 
          br.restriction_start_date DESC
      LIMIT ? OFFSET ?;
    `;

      // 쿼리 실행
      const results = await db.execute(query, [
        search,
        search,
        search,
        limit,
        offset,
      ]);

      // 전체 개수 조회 (페이징 처리용)
      const totalCount = await db.execute(
        `SELECT COUNT(*) AS total FROM book_restriction br
       LEFT JOIN notice n ON br.notice_id = n.notice_id
       LEFT JOIN user a ON br.admin_id = a.user_id
       WHERE br.restriction_end_date >= NOW()
       AND (n.title COLLATE utf8mb4_unicode_ci LIKE ? 
          OR a.name COLLATE utf8mb4_unicode_ci LIKE ? 
          OR DATE_FORMAT(br.restriction_start_date, '%Y-%m-%d %H:%i') COLLATE utf8mb4_unicode_ci LIKE ? 
          OR DATE_FORMAT(br.restriction_end_date, '%Y-%m-%d %H:%i') COLLATE utf8mb4_unicode_ci LIKE ?)`,
        [search, search, search, search]
      );

      // 응답 데이터 포맷
      const formattedResults = results.map((row) => ({
        restriction_uuid: row.restriction_uuid,
        notice_id: row.notice_id,
        notice_title: row.notice_title,
        admin_id: row.admin_id,
        admin_name: row.admin_name,
        seat_names: row.seat_names.split(","), // 좌석 이름 문자열을 배열로 변환
        restriction_start_date: row.restriction_start_date,
        restriction_end_date: row.restriction_end_date,
      }));

      res.status(200).json({
        success: true,
        currentPage: page,
        totalRestrictions: totalCount[0].total.toString(),
        restrictions: formattedResults,
      });
    } catch (err) {
      console.error("예약 제한 목록 조회 중 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: "예약 제한 목록을 조회하는 중 오류가 발생했습니다.",
      });
    }
  }
);
// 예약 제한 목록 조회 끝

// 특정 예약 제한 정보 조회 API 시작
router.get(
  "/book/restriction/:uuid",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { uuid } = req.params; // 예약 제한 ID 가져오기

    let connection;
    try {
      connection = await db.getConnection();

      // 예약 제한 정보 조회
      const rows = await connection.query(
        `
      SELECT 
        br.restriction_id,
        br.restriction_uuid,
        br.notice_id,
        n.title AS notice_title,
        DATE_FORMAT(br.restriction_start_date, '%Y-%m-%d %H:%i') AS startDate,
        DATE_FORMAT(br.restriction_end_date, '%Y-%m-%d %H:%i') AS endDate,
        br.seat_names
      FROM book_restriction br
      LEFT JOIN notice n ON br.notice_id = n.notice_id
      WHERE br.restriction_uuid = ?
      `,
        [uuid]
      );

      if (rows.length === 0) {
        res.status(404).json({
          success: false,
          message: "해당 예약 제한 정보를 찾을 수 없습니다.",
        });
        return;
      }
      const restrictionInfo = rows[0];

      // 좌석 데이터 파싱
      const seatNames = restrictionInfo.seat_names
        ? restrictionInfo.seat_names.split(",").map((seat) => seat.trim())
        : [];

      res.status(200).json({
        success: true,
        restrictions: {
          restriction_id: restrictionInfo.restriction_id,
          restriction_uuid: restrictionInfo.restriction_uuid,
          notice_id: restrictionInfo.notice_id,
          notice_title: restrictionInfo.notice_title,
          restriction_start_date: restrictionInfo.startDate,
          restriction_end_date: restrictionInfo.endDate,
          seat_names: seatNames,
        },
      });
    } catch (error) {
      console.error("예약 제한 정보를 조회하는 중 오류 발생:", error);
      res.status(500).json({
        success: false,
        message: "예약 제한 정보를 조회하는 중 서버 오류가 발생했습니다.",
      });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 특정 예약 제한 정보 조회 API 시작

// 예약 제한 생성 API 시작
router.post(
  "/book/restriction",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const {
      selectedSeats,
      seatNames,
      startDate,
      endDate,
      selectedNotice,
      userId,
    } = req.body;

    if (!selectedSeats || !startDate || !endDate || !seatNames) {
      res.status(400).json({
        success: false,
        message: "필수 입력값이 누락되었습니다.",
      });
    }

    let connection;
    try {
      connection = await db.getConnection();

      // 트랜잭션 시작
      await connection.beginTransaction();

      // 예약 제한 데이터 삽입
      const restrictionResult = await connection.query(
        `
      INSERT INTO book_restriction (seat_names, restriction_start_date, restriction_end_date, notice_id, admin_id) 
      VALUES (?, ?, ?, ?, ?)
      `,
        [seatNames, startDate, endDate, selectedNotice, userId]
      );

      const restrictionId = restrictionResult.insertId;

      // 예약 제한 생성 로그 기록
      await connection.query(
        `
      INSERT INTO logs (log_date, type, log_type, admin_id, restriction_id, notice_id) 
      VALUES (NOW(), 'create', 'restriction', ?, ?, ?)
      `,
        [userId, restrictionId, selectedNotice]
      );

      // 트랜잭션 커밋
      await connection.commit();
      connection.release();

      res.status(201).json({
        success: true,
        message: "예약 제한이 성공적으로 생성되었습니다.",
      });
    } catch (error) {
      console.error("예약 제한 생성 중 오류 발생:", error);

      if (connection) await connection.rollback();

      res.status(500).json({
        success: false,
        message: "예약 제한 생성 중 오류가 발생했습니다.",
      });
    }
  }
);
// 예약 제한 생성 API 끝

// 특정 예약 제한 수정 API 시작
router.patch(
  "/book/restriction/:uuid",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { uuid } = req.params; // 예약 제한 ID
    const {
      restrictionId,
      selectedSeats,
      seatNames,
      startDate,
      endDate,
      selectedNotice,
      userId,
    } = req.body;

    if (
      !selectedSeats ||
      !startDate ||
      !endDate ||
      !seatNames ||
      !restrictionId
    ) {
      res.status(400).json({
        success: false,
        message: "필수 입력값이 누락되었습니다.",
      });
      return;
    }

    let connection;
    try {
      connection = await db.getConnection();

      // 트랜잭션 시작
      await connection.beginTransaction();

      // 강제 퇴실 처리 (이미 예약된 좌석 처리)
      for (const seat of selectedSeats) {
        if (seat.state === "book") {
          const { seat_id: seatId } = seat;

          const reservation = await connection.query(
            `
          SELECT b.book_id, b.user_id, u.email, u.name, s.name AS seat_name
          FROM book b
          LEFT JOIN user u ON b.user_id = u.user_id
          LEFT JOIN seat s ON b.seat_id = s.seat_id
          WHERE b.seat_id = ? AND b.state = 'book' AND 
          b.book_date <= ? AND b.book_date >= ?
          `,
            [seatId, endDate, startDate]
          );

          if (reservation.length > 0) {
            const { book_id, email, name, seat_name } = reservation[0];

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
            INSERT INTO logs (book_id, log_date, type, log_type, reason, admin_id)
            VALUES (?, NOW(), 'cancel', 'book', '관리자 설정으로 좌석 예약이 제한되었습니다.', ?)
            `,
              [book_id, userId]
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
                <li><strong>퇴실 사유:</strong> 관리자 설정으로 좌석 예약이 제한되었습니다.</li>
              </ul>
              <p>문의사항이 있으시면 관리자에게 문의하세요.</p>
            `,
            };

            try {
              await transporter.sendMail(mailOptions);
            } catch (emailError) {
              console.error("이메일 전송 중 오류 발생:", emailError);
            }
          }
        }
      }

      // 예약 제한 업데이트
      await connection.query(
        `
      UPDATE book_restriction
      SET seat_names = ?, restriction_start_date = ?, restriction_end_date = ?, notice_id = ?
      WHERE restriction_uuid = ?
      `,
        [seatNames, startDate, endDate, selectedNotice, uuid]
      );

      // 예약 제한 수정 로그 기록
      await connection.query(
        `
      INSERT INTO logs (log_date, type, log_type, admin_id, restriction_id, notice_id)
      VALUES (NOW(), 'edit', 'restriction', ?, ?, ?)
      `,
        [userId, restrictionId, selectedNotice]
      );

      // 트랜잭션 커밋
      await connection.commit();
      connection.release();

      res.status(200).json({
        success: true,
        message: "예약 제한이 성공적으로 수정되었습니다.",
      });
    } catch (error) {
      console.error("예약 제한 수정 중 오류 발생:", error);

      if (connection) await connection.rollback();

      res.status(500).json({
        success: false,
        message: "예약 제한 수정 중 서버 오류가 발생했습니다.",
      });
    }
  }
);
// 특정 예약 제한 수정 API 끝

// 특정 예약 제한 삭제 API 시작
router.delete(
  "/book/restriction/:uuid",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { uuid } = req.params;
    const { restrictionId, userId } = req.body;

    let connection;
    try {
      connection = await db.getConnection();

      // 트랜잭션 시작
      await connection.beginTransaction();

      // 예약 제한 데이터 확인
      const restriction = await connection.query(
        `SELECT restriction_id, seat_names FROM book_restriction WHERE restriction_uuid = ?`,
        [uuid]
      );

      if (!restriction || restriction.length === 0) {
        res.status(404).json({
          success: false,
          message: "삭제할 예약 제한이 존재하지 않습니다.",
        });
      }

      // const seatNames = restriction[0].seat_names.split(", ").map((seat) => seat.trim());

      // 로그 기록
      await connection.query(
        `
      INSERT INTO logs (log_date, type, log_type, admin_id, restriction_id) 
      VALUES (NOW(), 'delete', 'restriction', ?, ? )
      `,
        [userId, restrictionId]
      );

      // 삭제 처리
      await connection.query(
        `DELETE FROM book_restriction WHERE restriction_uuid = ?`,
        [uuid]
      );

      // 트랜잭션 커밋
      await connection.commit();
      connection.release();

      res.status(200).json({
        success: true,
        message: "예약 제한이 성공적으로 삭제되었습니다.",
      });
    } catch (error) {
      console.error("예약 제한 삭제 중 오류 발생:", error);

      if (connection) await connection.rollback();
      res.status(500).json({
        success: false,
        message: "예약 제한 삭제 중 오류가 발생했습니다.",
      });
    }
  }
);
// 특정 예약 제한 삭제 API 끝

// 기본 설정 조회 API 시작
router.get(
  "/default-settings",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    try {
      const [settings] = await db.query(`
      SELECT 
        available_start_time, 
        available_end_time, 
        basic_manners 
      FROM default_settings 
      WHERE setting_id = 1
    `);

      if (!settings) {
        res
          .status(404)
          .json({ success: false, message: "설정 정보를 찾을 수 없습니다." });
      }

      res.status(200).json({
        success: true,
        data: settings,
      });
    } catch (error) {
      console.error("기본 설정 가져오기 중 오류 발생:", error);
      res.status(500).json({
        success: false,
        message: "기본 설정 가져오기 중 오류가 발생했습니다.",
      });
    }
  }
);
// 기본 설정 조회 API 끝

// 기본 설정 수정 API 시작
router.patch(
  "/default-settings",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { available_start_time, available_end_time, basic_manners, userId } =
      req.body;

    if (!available_start_time || !available_end_time || !basic_manners) {
      res
        .status(400)
        .json({ success: false, message: "필수 입력값이 누락되었습니다." });
      return;
    }

    if (available_start_time > available_end_time) {
      res.status(400).json({
        success: false,
        message: "예약 가능 시간이 올바르지 않습니다.",
      });
      return;
    }

    // 특수문자 검증 (허용되지 않는 특수문자 체크)
    if (
      !validator.isLength(basic_manners, { max: 200 }) ||
      /[`"<>-]/.test(basic_manners)
    ) {
      res.status(400).json({
        success: false,
        message:
          "퇴실 사유는 최대 200자의 문자열이며, <, >, `, - 기호는 허용되지 않습니다.",
      });
      return;
    }

    let connection;
    try {
      connection = await db.getConnection();
      await connection.beginTransaction();

      // **사용 가능 시작 시간 이전에 예약된 사용자 조회 (강제 퇴실 대상)**
      const reservations = await connection.query(
        `
      SELECT b.book_id, b.user_id, u.email, u.name, s.name AS seat_name 
      FROM book b
      LEFT JOIN user u ON b.user_id = u.user_id
      LEFT JOIN seat s ON b.seat_id = s.seat_id
      WHERE b.state = 'book' 
      AND TIME(b.book_date) < ?
      `,
        [available_start_time]
      );

      console.log(reservations);

      // **예약된 사용자 강제 퇴실 처리**
      for (const reservation of reservations) {
        const { book_id, email, name, seat_name } = reservation;

        // 예약 상태를 'cancel'로 업데이트
        await connection.query(
          `UPDATE book SET state = 'cancel' WHERE book_id = ? AND state = 'book'`,
          [book_id]
        );

        // 예약 로그 기록
        await connection.query(
          `
        INSERT INTO logs (book_id, log_date, type, log_type, reason, admin_id) 
        VALUES (?, NOW(), 'cancel', 'book', '예약 가능 시간 변경으로 인한 강제 퇴실', ?)
        `,
          [book_id, userId]
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
            <li><strong>퇴실 사유:</strong> 예약 가능 시간 변경으로 인한 강제 퇴실</li>
          </ul>
          <p>문의사항이 있으시면 관리자에게 문의하세요.</p>
        `,
        };

        try {
          await transporter.sendMail(mailOptions);
        } catch (emailError) {
          console.error("이메일 전송 중 오류 발생:", emailError);
        }
      }

      // **기본 설정 업데이트**
      const result = await connection.query(
        `
      UPDATE default_settings
      SET 
        available_start_time = ?, 
        available_end_time = ?, 
        basic_manners = ?
      WHERE setting_id = 1
      `,
        [available_start_time, available_end_time, basic_manners]
      );

      if (result.affectedRows === 0) {
        res.status(404).json({
          success: false,
          message: "업데이트할 설정 정보를 찾을 수 없습니다.",
        });
        return;
      }

      // **트랜잭션 커밋**
      await connection.commit();
      connection.release();

      // **스케줄러 재등록**
      await initializeForceExitScheduler();

      res.status(200).json({
        success: true,
        message:
          "설정 정보가 성공적으로 업데이트되었으며, 강제 퇴실이 완료되었습니다.",
      });
    } catch (error) {
      console.error("기본 설정 업데이트 중 오류 발생:", error);
      if (connection) await connection.rollback();
      res.status(500).json({
        success: false,
        message: "기본 설정 업데이트 중 오류가 발생했습니다.",
      });
    }
  }
);
// 기본 설정 수정 API 끝

// 좌석 정보 수정 API 시작 - 좌석 관리
router.patch(
  "/update-seat",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  upload.single("image"),
  async (
    req: Request & { existingImagePath?: string; file?: multer.File },
    res
  ) => {
    let { selectedSeats, warning, pcUsage } = req.body;
    try {
      // JSON으로 전송된 selectedSeats를 파싱
      selectedSeats = selectedSeats.split(",");

      // 유효성 검사
      if (
        !selectedSeats ||
        !Array.isArray(selectedSeats) ||
        selectedSeats.length === 0
      ) {
        res
          .status(400)
          .json({ success: false, message: "유효한 좌석 정보가 필요합니다." });
        return;
      }

      if (
        !validator.isLength(warning, { max: 100 }) ||
        allowedSymbols.test(warning)
      ) {
        res.status(400).json({
          success: false,
          message:
            "주의사항은 최대 100자의 문자열이며, <, >, `, -, ' 기호는 허용되지 않습니다.",
        });
        return;
      }

      // 이미지 경로 설정
      const imagePath = req.existingImagePath || `/image/${req.file.filename}`;

      let connection;
      try {
        connection = await db.getConnection();
        await connection.beginTransaction();

        for (const seat of selectedSeats) {
          await connection.query(
            `
          UPDATE seat
          SET 
            warning = ?, 
            pc_support = ?, 
            image_path = ?
          WHERE name = ?
          `,
            [warning || null, pcUsage || "none", imagePath, seat]
          );
        }

        await connection.commit();

        res.status(200).json({
          success: true,
          message: "좌석 정보가 성공적으로 수정되었습니다.",
        });
      } catch (err) {
        if (connection) await connection.rollback();
        console.error("좌석 정보 수정 중 오류 발생:", err);

        res.status(500).json({
          success: false,
          message: "좌석 정보 수정 중 오류가 발생했습니다.",
        });
      } finally {
        if (connection) connection.release();
      }
    } catch (err) {
      console.error("좌석 정보 수정 처리 중 오류:", err);
      res.status(500).json({
        success: false,
        message: "좌석 정보 수정 중 오류가 발생했습니다.",
      });
    }
  }
);
// 좌석 정보 수정 API 끝

// 사용자 강제 회원 탈퇴 API 시작
router.delete(
  "/users/withdrawal/:user_id",
  csrfProtection,
  limiter,
  authenticateToken,
  authorizeAdmin,
  async (req, res) => {
    const { user_id } = req.params;
    const userId = parseInt(user_id, 10);

    if (isNaN(userId)) {
      res
        .status(400)
        .json({ success: false, message: "유효한 사용자 ID가 필요합니다." });
      return;
    }

    let connection;
    try {
      connection = await db.getConnection();
      await connection.beginTransaction();

      // 사용자 정보 조회
      const [user] = await connection.query(
        `SELECT user_id, email, name FROM user WHERE user_id = ?`,
        [userId]
      );

      if (!user) {
        res
          .status(404)
          .json({ success: false, message: "사용자 정보를 찾을 수 없습니다." });
        return;
      }

      // 현재 예약 확인
      const reservations = await connection.query(
        `SELECT book_id FROM book WHERE user_id = ? AND state = 'book'`,
        [userId]
      );

      if (reservations.length > 0) {
        // 예약된 좌석 강제 퇴실 처리
        for (const reservation of reservations) {
          await connection.query(
            `UPDATE book SET state = 'cancel' WHERE book_id = ? AND state = 'book'`,
            [reservation.book_id]
          );

          // 로그 기록
          await connection.query(
            `INSERT INTO logs (book_id, log_date, type, log_type, reason) 
            VALUES (?, NOW(), 'cancel', 'book', '강제 회원 탈퇴로 인한 강제 퇴실')`,
            [reservation.book_id]
          );
        }
      }

      // 사용자 정보 삭제
      await connection.query(`DELETE FROM user WHERE user_id = ?`, [userId]);

      // 트랜잭션 커밋
      await connection.commit();
      connection.release();

      res.status(200).json({
        success: true,
        message:
          "사용자가 성공적으로 삭제되었으며, 예약 좌석도 강제 퇴실되었습니다.",
      });
    } catch (error) {
      console.error("사용자 삭제 중 오류 발생:", error);

      if (connection) await connection.rollback();

      res.status(500).json({
        success: false,
        message: "사용자 삭제 중 서버 오류가 발생했습니다.",
      });
    } finally {
      if (connection) connection.release();
    }
  }
);
// 사용자 강제 회원 탈퇴 API 끝

export default router;
