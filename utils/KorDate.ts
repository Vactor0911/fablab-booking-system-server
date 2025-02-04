interface KorDateProps {
  time?: number | string | Date | undefined;
}

const KorDate = ({ time }: KorDateProps = {}) => {
    return new Date(time ?? new Date()).toLocaleTimeString("en-US", {
        hour12: false,
        timeZone: "Asia/Seoul",
    });
};

export default KorDate;
