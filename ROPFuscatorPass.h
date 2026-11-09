#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct ROPFuscatorPass : llvm::PassInfoMixin<ROPFuscatorPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunROPFuscator(llvm::Module& m);

extern llvm::cl::opt<bool> ROPFuscatorEnable;