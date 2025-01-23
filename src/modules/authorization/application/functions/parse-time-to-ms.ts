// Helper method to parse time strings like "5s", "1h", "3d" to milliseconds
export const parseTimeToMs = (timeStr: string): number => {
  const unit = timeStr.slice(-1);
  const value = parseInt(timeStr.slice(0, -1));

  switch (unit) {
    case 's':
      return value * 1000; // seconds to ms
    case 'm':
      return value * 60 * 1000; // minutes to ms
    case 'h':
      return value * 60 * 60 * 1000; // hours to ms
    case 'd':
      return value * 24 * 60 * 60 * 1000; // days to ms
    default:
      throw new Error('Unsupported time unit');
  }
};
