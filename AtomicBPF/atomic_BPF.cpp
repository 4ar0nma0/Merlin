//=============================================================================
// FILE:
//    atomic_BPF.cpp
//
// DESCRIPTION:
//    Merge read-modify-write sequence into an atomicRMW instruction
//
// USAGE:
//    opt -load-pass-plugin=libAtomicBPF.so -passes=atomicbpf -o output
//
//=============================================================================
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/AtomicOrdering.h"

using namespace llvm;

//-----------------------------------------------------------------------------
// Implementation
//-----------------------------------------------------------------------------
namespace {
    auto convert_rmw_op(int op_type) {
        switch (op_type) {
            case Instruction::Add:
                return AtomicRMWInst::BinOp::Add;
            case Instruction::Xor:
                return AtomicRMWInst::BinOp::Xor;
            case Instruction::Or:
                return AtomicRMWInst::BinOp::Or;
            case Instruction::And:
                return AtomicRMWInst::BinOp::And;
        }
    }

    // Main entry
    void atomic_merge(Function &F) {
            int opt_cnt = 0;
            // change the verbosity here
            bool verbose = 0;
            Value* operand;
            for (auto &BB: F) {
                for (auto &I: BB) {
                    int a = BB.size();
                    // Check if is load inst, as we optimize read-modify-store
                    // We only merge consecutive read-modify-store sequence
                    if (auto *Ld = dyn_cast<LoadInst>(&I)) {
                        //  Check if Binary operation satisfies
                        if (auto *BinOpt = dyn_cast<BinaryOperator>(Ld->getNextNode())) {
                            if (BinOpt->getOperand(0) == Ld){
                                operand = BinOpt->getOperand(1);
                            }else if (BinOpt->getOperand(1) != Ld) {
                                operand = BinOpt->getOperand(0);
                            }else{
                                continue;
                            }

                            // 64-bit operation, supported by ebpf architecture
                            if(operand->getType()->isIntegerTy(64)){
                                // check the alignment of memory operations
                                if (Ld->getAlign().value() < 8) {
                                    continue;
                                }
                            }else if(operand->getType()->isIntegerTy(32)){
                                // check the alignment of memory operations
                                if (Ld->getAlign().value() < 4) {
                                    continue;
                                }else if (BinOpt->getOpcode()==Instruction::Or){
                                    // Note: ebpf does not support 32-bit atomic or instruction
                                    continue;
                                }
                            }else{
                                continue;
                            }

                            // ebpf only supports 4 types of atomic instructions
                            auto op_type = BinOpt->getOpcode();
                            if (op_type == Instruction::Add || op_type == Instruction::Or ||
                                op_type == Instruction::Xor || op_type == Instruction::And) {
                                if (auto *St = dyn_cast<StoreInst>(BinOpt->getNextNode())) {
                                    if (Ld->getPointerOperand() == St->getPointerOperand()) {
                                        // We found a load-add-store sequence that can be
                                        // replaced with an atomicRMW instruction.
                                        if (verbose) {
                                            errs() << "we found a potential atomic optimization: \n" <<
                                               *Ld << "\n" << *BinOpt << "\n" << *St << "\n";
                                            opt_cnt += 1;
                                        }

                                        // Read and modify instructions will be deleted
                                        // They should only have one consumer
                                        if (!Ld->hasOneUser() || !BinOpt->hasOneUser()){
                                            continue;
                                        }

                                        // Build the new atomicRMW instructions
                                        IRBuilder<> Builder(BinOpt);
                                        Builder.SetInsertPoint(BinOpt);
                                        AtomicRMWInst *RMW =
                                                Builder.CreateAtomicRMW(convert_rmw_op(op_type),
                                                                        Ld->getPointerOperand(),
                                                                        operand,
                                                                        St->getAlign(),
                                                                        AtomicOrdering::Monotonic);

                                        // Currently we do not support atomic exchange
                                        // BinOpt->replaceAllUsesWith(RMW);

                                        // Delete certain instructions
                                        BinOpt->eraseFromParent();
                                        St->eraseFromParent();
                                    }
                                }
                            }
                        }
                    }
                    int b = BB.size();
                    if (verbose && (a != b)){
                        errs() << "Handling " << F.getName() << ". Removed " << a-b << " instructions\n";
                    }
                }
            }
        }

    // New PM implementation
    struct AtomicBPF : PassInfoMixin<AtomicBPF> {
        // Main entry point, takes IR unit to run the pass on (&F) and the
        // corresponding pass manager (to be queried if need be)
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
            atomic_merge(F);
            return PreservedAnalyses::all();
        }
        static bool isRequired() { return true; }
    };

    // Legacy PM implementation, but absolutely no warranty for it
    struct LegacyAtomicBPF : public FunctionPass {
        static char ID;
        LegacyAtomicBPF() : FunctionPass(ID) {}
        bool runOnFunction(Function &F) override {
            atomic_merge(F);
            return false;
        }
    };
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getAtomicBPFPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "AtomicBPF", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                        [](StringRef Name, FunctionPassManager &FPM,
                           ArrayRef<PassBuilder::PipelineElement>) {
                            if (Name == "atomicbpf") {
                                FPM.addPass(AtomicBPF());
                                return true;
                            }
                            return false;
                        });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return getAtomicBPFPluginInfo();
}

//-----------------------------------------------------------------------------
// Legacy PM Registration, absolutely no warranty for it
//-----------------------------------------------------------------------------
char LegacyAtomicBPF::ID = 0;
static RegisterPass<LegacyAtomicBPF>
        X("atomicbpf", "BPF Atomic Optimization",
          false,
          false
);