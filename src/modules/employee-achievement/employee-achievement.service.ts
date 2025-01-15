import { paginationHelpers } from "@/lib/paginationHelper";
import { PaginationType } from "@/types";
import { PipelineStage } from "mongoose";
import { EmployeeAchievement } from "./employee-achievement.model";
import {
  EmployeeAchievementFilterOptions,
  EmployeeAchievementType,
} from "./employee-achievement.type";

// get all data
const getAllEmployeeAchievementService = async (
  paginationOptions: Partial<PaginationType>,
  filterOptions: Partial<EmployeeAchievementFilterOptions>
) => {
  let matchStage: any = {
    $match: {},
  };
  const { limit, skip } =
    paginationHelpers.calculatePagination(paginationOptions);

  // Extract search and filter options
  const { search } = filterOptions;

  // Search condition
  if (search) {
    const searchKeyword = String(search).replace(/\+/g, " ");
    const keywords = searchKeyword.split("|");
    const searchConditions = keywords.map((keyword) => ({
      $or: [{ employee_id: { $regex: keyword, $options: "i" } }],
    }));
    matchStage.$match.$or = searchConditions;
  }

  let pipeline: PipelineStage[] = [matchStage];

  pipeline.push({ $sort: { updatedAt: -1 } });

  if (skip) {
    pipeline.push({ $skip: skip });
  }
  if (limit) {
    pipeline.push({ $limit: limit });
  }

  pipeline.push(
    {
      $lookup: {
        from: "employees",
        localField: "employee_id",
        foreignField: "id",
        as: "employee",
      },
    },
    {
      $project: {
        _id: 0,
        employee_id: 1,
        achievements: 1,
        "employee.name": 1,
        "employee.image": 1,
      },
    }
  );

  const result = await EmployeeAchievement.aggregate(pipeline);
  const total = await EmployeeAchievement.countDocuments();
  return {
    result: result,
    meta: {
      total: total,
    },
  };
};

// get single data
const getEmployeeAchievementService = async (id: string) => {
  const result = await EmployeeAchievement.findOne({ employee_id: id });
  return result;
};

// add or update
const updateEmployeeAchievementService = async (
  id: string,
  updateData: EmployeeAchievementType
) => {
  const achievement = await EmployeeAchievement.findOne({ platform: id });

  if (achievement) {
    // Update existing achievements or add new ones
    updateData.achievements.forEach((newAchievement) => {
      const existingAchievementIndex = achievement.achievements.findIndex(
        (achievement) => achievement.name === newAchievement.name
      );
      if (existingAchievementIndex !== -1) {
        // Update existing achievement
        achievement.achievements[existingAchievementIndex] = {
          ...achievement.achievements[existingAchievementIndex],
          ...newAchievement,
        };
      } else {
        // Add new achievement
        achievement.achievements.push(newAchievement);
      }
    });
    await achievement.save();
    return achievement;
  } else {
    // Create new achievement if it doesn't exist
    const newEmployeeAchievement = new EmployeeAchievement(updateData);
    await newEmployeeAchievement.save();
    return newEmployeeAchievement;
  }
};

// delete
const deleteEmployeeAchievementService = async (id: string) => {
  await EmployeeAchievement.findOneAndDelete({ employee_id: id });
};

export const employeeAchievementService = {
  getAllEmployeeAchievementService,
  getEmployeeAchievementService,
  deleteEmployeeAchievementService,
  updateEmployeeAchievementService,
};
