"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.employeeAchievementService = void 0;
const paginationHelper_1 = require("../../lib/paginationHelper");
const employee_achievement_model_1 = require("./employee-achievement.model");
// get all data
const getAllEmployeeAchievementService = (paginationOptions, filterOptions) => __awaiter(void 0, void 0, void 0, function* () {
    let matchStage = {
        $match: {},
    };
    const { limit, skip } = paginationHelper_1.paginationHelpers.calculatePagination(paginationOptions);
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
    let pipeline = [matchStage];
    pipeline.push({ $sort: { updatedAt: -1 } });
    if (skip) {
        pipeline.push({ $skip: skip });
    }
    if (limit) {
        pipeline.push({ $limit: limit });
    }
    pipeline.push({
        $lookup: {
            from: "employees",
            localField: "employee_id",
            foreignField: "id",
            as: "employee",
        },
    }, {
        $project: {
            _id: 0,
            employee_id: 1,
            achievements: 1,
            "employee.name": 1,
            "employee.image": 1,
        },
    });
    const result = yield employee_achievement_model_1.EmployeeAchievement.aggregate(pipeline);
    const total = yield employee_achievement_model_1.EmployeeAchievement.countDocuments();
    return {
        result: result,
        meta: {
            total: total,
        },
    };
});
// get single data
const getEmployeeAchievementService = (id) => __awaiter(void 0, void 0, void 0, function* () {
    const result = yield employee_achievement_model_1.EmployeeAchievement.findOne({ employee_id: id });
    return result;
});
// add or update
const updateEmployeeAchievementService = (id, updateData) => __awaiter(void 0, void 0, void 0, function* () {
    const achievement = yield employee_achievement_model_1.EmployeeAchievement.findOne({ platform: id });
    if (achievement) {
        // Update existing achievements or add new ones
        updateData.achievements.forEach((newAchievement) => {
            const existingAchievementIndex = achievement.achievements.findIndex((achievement) => achievement.name === newAchievement.name);
            if (existingAchievementIndex !== -1) {
                // Update existing achievement
                achievement.achievements[existingAchievementIndex] = Object.assign(Object.assign({}, achievement.achievements[existingAchievementIndex]), newAchievement);
            }
            else {
                // Add new achievement
                achievement.achievements.push(newAchievement);
            }
        });
        yield achievement.save();
        return achievement;
    }
    else {
        // Create new achievement if it doesn't exist
        const newEmployeeAchievement = new employee_achievement_model_1.EmployeeAchievement(updateData);
        yield newEmployeeAchievement.save();
        return newEmployeeAchievement;
    }
});
// delete
const deleteEmployeeAchievementService = (id) => __awaiter(void 0, void 0, void 0, function* () {
    yield employee_achievement_model_1.EmployeeAchievement.findOneAndDelete({ employee_id: id });
});
exports.employeeAchievementService = {
    getAllEmployeeAchievementService,
    getEmployeeAchievementService,
    deleteEmployeeAchievementService,
    updateEmployeeAchievementService,
};
//# sourceMappingURL=employee-achievement.service.js.map