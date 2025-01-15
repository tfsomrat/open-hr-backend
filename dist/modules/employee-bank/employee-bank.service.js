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
exports.employeeBankService = void 0;
const paginationHelper_1 = require("../../lib/paginationHelper");
const employee_bank_model_1 = require("./employee-bank.model");
// get all data
const getAllEmployeeBankService = (paginationOptions, filterOptions) => __awaiter(void 0, void 0, void 0, function* () {
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
            banks: 1,
            "employee.name": 1,
            "employee.image": 1,
        },
    });
    const result = yield employee_bank_model_1.EmployeeBank.aggregate(pipeline);
    const total = yield employee_bank_model_1.EmployeeBank.countDocuments();
    return {
        result: result,
        meta: {
            total: total,
        },
    };
});
// get single data
const getEmployeeBankService = (id) => __awaiter(void 0, void 0, void 0, function* () {
    const result = yield employee_bank_model_1.EmployeeBank.findOne({ employee_id: id });
    return result;
});
// add or update
const updateEmployeeBankService = (id, updateData) => __awaiter(void 0, void 0, void 0, function* () {
    const bank = yield employee_bank_model_1.EmployeeBank.findOne({ platform: id });
    if (bank) {
        // Update existing banks or add new ones
        updateData.banks.forEach((newBank) => {
            const existingBankIndex = bank.banks.findIndex((bank) => bank.bank_name === newBank.bank_name);
            if (existingBankIndex !== -1) {
                // Update existing bank
                bank.banks[existingBankIndex] = Object.assign(Object.assign({}, bank.banks[existingBankIndex]), newBank);
            }
            else {
                // Add new bank
                bank.banks.push(newBank);
            }
        });
        yield bank.save();
        return bank;
    }
    else {
        // Create new bank if it doesn't exist
        const newEmployeeBank = new employee_bank_model_1.EmployeeBank(updateData);
        yield newEmployeeBank.save();
        return newEmployeeBank;
    }
});
// delete
const deleteEmployeeBankService = (id) => __awaiter(void 0, void 0, void 0, function* () {
    yield employee_bank_model_1.EmployeeBank.findOneAndDelete({ employee_id: id });
});
exports.employeeBankService = {
    getAllEmployeeBankService,
    getEmployeeBankService,
    deleteEmployeeBankService,
    updateEmployeeBankService,
};
//# sourceMappingURL=employee-bank.service.js.map