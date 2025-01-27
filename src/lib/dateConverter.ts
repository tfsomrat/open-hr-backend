import { add, format } from "date-fns";

export const formatDate = (
  date: string | number | Date,
  pattern: string = "EEEE, dd MMMM, yyyy"
) => {
  if (!date) return;
  const dateObj = new Date(date);
  const output = format(dateObj, pattern);
  return output;
};

export const localDate = (date: Date) => {
  const removeTime = new Date(date).toISOString().split("T")[0];
  const utcDate = new Date(removeTime);
  const dhakaTime = add(utcDate, { hours: 6 });
  return dhakaTime;
};

export const isOneYearPassed = (prevDate: Date, currentDate: Date) => {
  const oneYearLater = new Date(prevDate);
  oneYearLater.setFullYear(oneYearLater.getFullYear() + 1);

  // Compare only the date values
  const isPassed =
    oneYearLater.getFullYear() < currentDate.getFullYear() ||
    (oneYearLater.getFullYear() === currentDate.getFullYear() &&
      oneYearLater.getMonth() < currentDate.getMonth()) ||
    (oneYearLater.getFullYear() === currentDate.getFullYear() &&
      oneYearLater.getMonth() === currentDate.getMonth() &&
      oneYearLater.getDate() <= currentDate.getDate());

  return isPassed;
};
