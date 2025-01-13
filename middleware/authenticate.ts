import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";

// Request 인터페이스를 확장하여 user 속성을 포함합니다.
declare module "express-serve-static-core" {
  interface Request {
    user?: any;
  }
}

// 사용자 인증 미들웨어
export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const accessToken = req.cookies?.accessToken;

  if (!accessToken) {
    res.status(403).json({
      success: false,
      message: "Access Token이 필요합니다.",
    });
    return; // 반드시 반환
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET!);
    req.user = decoded; // 사용자 정보를 요청 객체에 저장
    next(); // 다음 미들웨어로 이동
  } catch (err) {
    res.status(403).json({
      success: false,
      message: "유효하지 않은 Access Token입니다.",
    });
    return; // 반드시 반환
  }
};

// 관리자 권한 인증 미들웨어
export const authorizeAdmin = (req: Request, res: Response, next: NextFunction): void => {
  const user = req.user as { permission: string };

  if (!user || (user.permission !== "admin" && user.permission !== "superadmin")) {
    res.status(403).json({ success: false, message: "관리자 권한이 필요합니다." });
    return; // 반드시 반환
  }

  next(); // 다음 미들웨어로 이동
};
