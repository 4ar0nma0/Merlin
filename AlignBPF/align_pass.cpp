//=============================================================================
// FILE:
//    align_pass.cpp
//
// DESCRIPTION:
//    Revise the alignment of memory instructions
//
// USAGE:
//    opt -load-pass-plugin=libAtomicBPF.so -passes=alignbpf -o output
//
//=============================================================================

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include <regex>

using namespace llvm;

//-----------------------------------------------------------------------------
// Implementation
//-----------------------------------------------------------------------------
namespace {

    struct ptr_info {
        //---------------------------------------------------------------------
        // ptr_info stores necessary information for determining offset
        // id         -> the id of the pointer
        // off        -> current accumulated offset
        // stack_size -> if the value is stored in stack, shows the size in stack
        // is_exotic  -> if the pointer is a context pointer or a map pointer
        //---------------------------------------------------------------------
        uint32_t id;
        int off;
        uint32_t stack_size;
        int is_exotic;
    };

    uint32_t align_mapping(uint32_t size){
        // Match the size with alignment.
        if ((size >= 8) && (size % 8 == 0)){
            return 8;
        }else if ((size >= 4) && (size % 4 == 0)){
            return 4;
        }else if ((size >= 2) && (size % 2 == 0)){
            return 2;
        }
        return 1;
    }

    // Update necessary information about all the pointers
    auto get_ptr_align_off(Function &F){
        uint32_t ptr_id = 0;
        DataLayout DL = F.getParent()->getDataLayout();
        // Every pointer will be renamed to ptr_id
        // and the name will match a ptr_info
        std::map<std::string, ptr_info> PtrInfo;

        // bpf_cxt. There should only be one argument, but we still iterate all.
        for (auto arg = F.arg_begin(), arg_end = F.arg_end(); arg != arg_end; ++arg) {
            if (arg->getType()->isPointerTy()){
                std::stringstream ss;
                ss << "ptr_" << ptr_id;
                arg->setName(ss.str());
                PtrInfo[ss.str()] = ptr_info{ptr_id, 0, 0, 1};
                ptr_id += 1;
            }
        }

        for (auto &BB: F) {
            for (auto &I: BB){
                uint ptr_align;
                int ptr_off;
                if (I.getType()->isPointerTy()){

                    // set pointer name
                    std::stringstream ss;
                    ss << "ptr_" << ptr_id;
                    I.setName(ss.str());

                    // converting int to pointer.
                    // typically is from stack/map
                    if (auto *IntPtr = dyn_cast<IntToPtrInst>( &I)){
                        PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                     0,
                                                     0,
                                                     1};
                    }
                    // alloca instruction, typically assign stack space
                    else if (auto *AllocaPtr = dyn_cast<AllocaInst>( &I)){
                        llvm::Type *elementType = AllocaPtr->getAllocatedType();
                        ptr_align = DL.getTypeAllocSize(elementType);
                        PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                     0,
                                                     ptr_align,
                                                     0};
                        AllocaPtr->setAlignment(Align(align_mapping(ptr_align)));
                    }
                    // from bpf helpers or local functions
                    // maybe kfuns in the future
                    else if (auto *CallPtr = dyn_cast<CallInst>( &I)){
                        PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                     0,
                                                     0,
                                                     1};
                    }
                    // bitcast casts pointer to different types
                    // e.g. i8* -> i16*
                    else if (auto *BitCastPtr = dyn_cast<BitCastInst>( &I)){
                        //  bitcast keeps the original alignment and offset
                        auto PtrSrc = BitCastPtr->getOperand(0)->getName().str();
                        auto PtrSrcInfo = PtrInfo[PtrSrc];
                        PtrInfo[ss.str()] = PtrSrcInfo;
                        PtrInfo[ss.str()].id = ptr_id;
                    }
                    // gep instruction calculates the offset
                    // based on existing pointer and its types
                    else if (auto *GEPPtr = dyn_cast<GetElementPtrInst>(&I)){
                        auto PtrSrc = GEPPtr->getPointerOperand()->getName().str();
                        auto PtrSrcInfo = PtrInfo[PtrSrc];
                        auto num_operands = GEPPtr->getNumOperands();
                        int offset = 0;
                        int not_int_flag = 0;
                        int BaseSize;
                        Type *BaseType = GEPPtr->getSourceElementType();

                        // https://llvm.org/docs/GetElementPtr.html
                        for (auto idx = 1; idx != num_operands; ++idx) {
                            auto OffOperand = GEPPtr->getOperand(idx);
                            if (not isa<Constant>(OffOperand)) {
                                PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                             0,
                                                             PtrSrcInfo.stack_size,
                                                             1
                                };
                                not_int_flag = 1;
                                break;
                            }else{
                                int off = (int) dyn_cast<ConstantInt>(OffOperand)->getSExtValue();
                                if (idx == 1){
                                    BaseSize = (int) DL.getTypeAllocSize(BaseType).getFixedValue();
                                    offset += off * BaseSize;
                                }else{
                                    assert(off >= 0);
                                    if (auto *STy = dyn_cast<StructType>(BaseType)){
                                        for (auto i=0; i!= off; i++){
                                            BaseType = STy->getElementType((uint32_t) i);
                                            BaseSize = (int) DL.getTypeAllocSize(BaseType).getFixedValue();
                                            offset += BaseSize;
                                        }
                                        BaseType = STy->getElementType((uint32_t) off);
                                    }else if(auto *Ary = dyn_cast<ArrayType>(BaseType)){
                                        BaseType = Ary->getArrayElementType();
                                        BaseSize = (int) DL.getTypeAllocSize(BaseType).getFixedValue();
                                        offset += off * BaseSize;
                                    }else if(auto *Vec = dyn_cast<VectorType>(BaseType)){
                                        BaseType = Vec->getElementType();
                                        BaseSize = (int) DL.getTypeAllocSize(BaseType).getFixedValue();
                                        offset += off * BaseSize;
                                    }else{
                                        assert(false);
                                    }
                                }
                            }
                        }

                        if (not not_int_flag){
                            PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                         PtrSrcInfo.off + offset,
                                                         PtrSrcInfo.stack_size,
                                                         PtrSrcInfo.is_exotic};
                        }


                    }
                    // pointer from load instruction
                    // rare in bpf?
                    else if (auto *LdPtr = dyn_cast<LoadInst>(&I)){
                        auto PtrSrcInfo = PtrInfo[LdPtr->getPointerOperand()->getName().str()];
                        PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                     0,
                                                     0,
                                                     PtrSrcInfo.is_exotic};
                    }
                    // phinode
                    else if (auto *PhiPtr = dyn_cast<PHINode>(&I)){
                        int exotic = 1;
                        for (int i=0;i<PhiPtr->getNumIncomingValues();i++){
                            if (auto *NPtr = dyn_cast<ConstantPointerNull>(PhiPtr->getIncomingValue(i))) {continue;}
                            auto PtrSrcInfo = PtrInfo[PhiPtr->getIncomingValue(i)->getName().str()];
                            exotic = PtrSrcInfo.is_exotic * exotic;
                            ptr_off = PtrSrcInfo.off;
                        }
                        PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                     ptr_off,
                                                     0,
                                                     exotic};
                    }
                    // select instruction
                    else if (auto *SelPtr = dyn_cast<SelectInst>(&I)){
                        auto PtrSrc = SelPtr->getOperand(1)->getName().str();
                        auto PtrSrcInfo = PtrInfo[PtrSrc];
                        PtrInfo[ss.str()] = ptr_info{ptr_id,
                                                     PtrSrcInfo.off,
                                                     PtrSrcInfo.stack_size,
                                                     PtrSrcInfo.is_exotic};
                    }
                    ptr_id += 1;
                }
            }
        }
        return PtrInfo;
    }


    uint32_t get_new_alignment(Value* PtrVal, uint32_t size, uint32_t align, std::map<std::string, ptr_info> PtrInfo){
        auto info = PtrInfo[PtrVal->getName().str()];
        // This pass does not classify map pointer, context pointer and other pointers in detail
        // These are classified into 'exotic'
        // Typically you can assume 'exotic' pointers are well-aligned
        // If you wish to be aggressive, uncomment following lines.
        // Please use mcpu=v2 when testing.

        // if (info.is_exotic){
        //     return size > 8 ? 8: size;
        // }

        // calculate the new alignment according to offset
        uint32_t new_align;
        if (info.off % 8 == 0){
            new_align = 8;
        }else if (info.off % 4 == 0){
            new_align = 4;
        }else if (info.off % 2 == 0){
            new_align = 2;
        }else {
            new_align = 1;}

        // stack values align according to the assignment instead of offset
        // because unsure of offset at compile time
        uint32_t stack_align = new_align;
        if(info.stack_size){
            if (info.stack_size % 8 == 0){
                stack_align = 8;
            }else if (info.stack_size % 4 == 0){
                stack_align = 4;
            }else if (info.stack_size % 2 == 0){
                stack_align = 2;
            }else {
                stack_align = 1;}
        }
        new_align = new_align > stack_align ? stack_align : new_align;

        if (new_align >= align){
            return new_align;
        }else{
            return align;
        }
    }

    // Main Entry
    void fix_align(Function &F) {
        // Set verbosity here
        bool verbose = 0;
        // get all the pointer information
        auto PtrInfo = get_ptr_align_off(F);
        DataLayout DL = F.getParent()->getDataLayout();

        for (auto &BB: F) {
            for (auto &I: BB) {
                // Iterate all instructions and find store / load instructions
                if (auto *St = dyn_cast<StoreInst>( &I)){
                    auto ptr = St->getPointerOperand();
                    auto st_size = (uint32_t) DL.getTypeAllocSize(St->getValueOperand()->getType());
                    uint32_t new_align = get_new_alignment(ptr, st_size, St->getAlign().value(), PtrInfo);
                    if (verbose) {
                        errs() << "Handling: " << *St << "\n";
                        errs() << "Original Align: " << St->getAlign().value() <<
                            ". New Align: " << new_align << ". Size: " << st_size << "\n";
                    }

                    St->setAlignment(Align(new_align));
                }
                else if(auto *Ld = dyn_cast<LoadInst>( &I)){
                    auto ptr = Ld->getPointerOperand();
                    auto ld_size = (uint32_t) DL.getTypeAllocSize(Ld->getType());
                    uint32_t new_align = get_new_alignment(ptr, ld_size, Ld->getAlign().value(), PtrInfo);
                    if (verbose) {
                        errs()  << "Handling: " << *Ld << "\n";
                        errs() << "Original Align: " << Ld->getAlign().value() <<
                            ". New Align: " << new_align << ". Size: " << ld_size << "\n";
                    }
                    Ld->setAlignment(Align(new_align));
                }
                // Sometimes LLVM use built-in memcpy method
                // Here is an example.
                // If you find your program not properly fixed, add support here
                else if(auto *Cp = dyn_cast<CallInst>( &I)){
                    if (Cp->getCalledFunction() &&
                        Cp->getCalledFunction()->getName().startswith("llvm.memcpy.p0.p0.i64")){

                        // The first two arguments are pointers
                        auto ptr_1 = Cp->getOperand(0);
                        auto ptr_2 = Cp->getOperand(1);

                        uint32_t align_0 = get_new_alignment(ptr_1, 8,
                                                             1,
                                                             PtrInfo);
                        uint32_t align_1 = get_new_alignment(ptr_2, 8,
                                                             1,
                                                             PtrInfo);

                        auto al = Cp->getAttributes();
                        al = al.removeAttributeAtIndex(F.getContext(), 1, Attribute::Alignment);
                        al = al.removeAttributeAtIndex(F.getContext(), 2, Attribute::Alignment);


                        Attribute at = Attribute::get(F.getContext(), Attribute::Alignment, align_0);
                        al = al.addAttributeAtIndex(F.getContext(), 1, at);
                        at = Attribute::get(F.getContext(), Attribute::Alignment, align_1);
                        al = al.addAttributeAtIndex(F.getContext(), 2, at);

                        Cp->setAttributes(al);
                    }
                }
            }
        }


    }

    // New PM implementation
    struct AlignBPF : PassInfoMixin<AlignBPF> {
        // Main entry point, takes IR unit to run the pass on (&F) and the
        // corresponding pass manager (to be queried if need be)
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
            fix_align(F);
            return PreservedAnalyses::all();
        }
        static bool isRequired() { return true; }
    };

    // Legacy PM implementation, but absolutely no warranty for it
    struct LegacyAlignBPF : public FunctionPass {
        static char ID;
        LegacyAlignBPF() : FunctionPass(ID) {}
        bool runOnFunction(Function &F) override {
            fix_align(F);
            return false;
        }
    };
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getAlignBPFPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "AlignBPF", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                        [](StringRef Name, FunctionPassManager &FPM,
                           ArrayRef<PassBuilder::PipelineElement>) {
                            if (Name == "alignbpf") {
                                FPM.addPass(AlignBPF());
                                return true;
                            }
                            return false;
                        });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return getAlignBPFPluginInfo();
}

//-----------------------------------------------------------------------------
// Legacy PM Registration, absolutely no warranty for it
//-----------------------------------------------------------------------------
char LegacyAlignBPF::ID = 0;
static RegisterPass<LegacyAlignBPF>
        X("alignbpf", "BPF Alignment Optimization",
          false,
          false
);