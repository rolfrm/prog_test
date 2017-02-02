
#include<iron/full.h>
#include "persist.h"
#include "sortable.h"
#include "index_table.h"

typedef u64 codepoint;

typedef struct{
  void (* emit_symbol)(const char * symbolname);
  codepoint (* emit_function_begin)();
  void (* emit_function_end)();
  void (* emit_rewind)(codepoint pt);
  codepoint (* emit_function_body_begin)();
  void (* emit_function_body_end)();
  codepoint (* emit_funcall_begin)();
  void (* emit_funcall_end)();
  codepoint (*emit_parse_type_begin)();
  void (* emit_parse_type_end)();
}parser_context;


char * take_while(char * data, bool (* fcn)(char char_code)){
  while(fcn(data[0])) data++;
  return data;
}

static bool is_whitespace(char c){
  return (c == ' ') || (c == '\t') || (c == '\n');
}

bool is_endexpr(char c){
  return c == ',' || c == '{' || c == '}' || c == ')' || c == '(' || is_whitespace(c) || c == 0 || c ==';';
}

bool is_keyword_char(char c){
  return !is_endexpr(c);
}

char * parse_single_line_comment(char * code){
  bool is_comment(char c){
    return c != '\n';
  }
  if(*code != ';')
    return NULL;
  return take_while(code, is_comment) + 1;
}

char * parse_symbol(parser_context ctx, char * code){
  code = take_while(code, is_whitespace);
  char * end = take_while(code, is_keyword_char);
  char buf[end - code + 1];
  memcpy(buf, code, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  ctx.emit_symbol(buf);
  return end;
}
 
char * parse_function_invocation(parser_context ctx, char * code){
  auto pt = ctx.emit_funcall_begin();
  code = parse_symbol(ctx, code);
  if(code == NULL){
    ctx.emit_rewind(pt);
    return NULL;
  }
  code = take_while(code, is_whitespace);
  if(*code != '('){
    ctx.emit_rewind(pt);
    return NULL;
  }
 next_arg:

  code += 1;
  code = take_while(code, is_whitespace);
  char * c = parse_function_invocation(ctx, code);
  if(c == NULL){
    c = parse_symbol(ctx, code);
    if(c == NULL){
      ctx.emit_rewind(pt);
      return NULL;
    }
  }
  code = c;
  logd("CODE: %s\n", code);
  code = take_while(code, is_whitespace);
  if(*code == ','){
    goto next_arg;
  }else if(*code == ')'){
    ctx.emit_funcall_end();
    return code + 1;
  }
  ctx.emit_rewind(pt);
  return NULL;
}

char * parse_type(parser_context ctx, char * code){
  auto pt = ctx.emit_parse_type_begin();
  char * fun = parse_function_invocation(ctx, code);
  if(!fun){
    char * sym = parse_symbol(ctx, code);
    if(!sym){
      ctx.emit_rewind(pt);
      return NULL;
    }
    code = sym;
  }else{
    code = fun;
  }
  ctx.emit_parse_type_end();
  return code;
}
 
char * parse_function_def(parser_context ctx, char * code){
  code = take_while(code, is_whitespace);
  if(*code == 0) return NULL;

  auto pt = ctx.emit_function_begin();
  code = parse_type(ctx, code);
  if(code == NULL){
    ctx.emit_rewind(pt);
    return NULL;
  }

  {
    // parse name
    code = parse_symbol(ctx, code);
    if(*code == 0){
      ctx.emit_rewind(pt);
      return NULL;
    }
  }

  
  {// parse args
    code = take_while(code, is_whitespace);
    if(*code != '('){
      ctx.emit_rewind(pt);
      return NULL;
    }

  parse_next_symbol:
    code += 1;
    code = parse_type(ctx, code);
    if(code == NULL){
      ctx.emit_rewind(pt);
      return NULL;
    }
    code = take_while(code, is_whitespace);
    code = parse_symbol(ctx, code);
    if(code == NULL){
      ctx.emit_rewind(pt);
      return NULL;
    }
    if(*code == ',')
      goto parse_next_symbol;
    if(*code != ')'){
      ctx.emit_rewind(pt);
      return NULL;
    }
    code += 1;
  }

  { // parse body
    code = take_while(code, is_whitespace);
    if(*code != '{'){
      ctx.emit_rewind(pt);
      return NULL;
    }
    code += 1;
    ctx.emit_function_body_begin();
  next_statement:
    code = take_while(code, is_whitespace);
    if(*code != '}'){
      char * finv = parse_function_invocation(ctx, code);
      if(!finv){
	ctx.emit_rewind(pt);
	return NULL;
      }
      code = finv;
      code = take_while(code, is_whitespace);
      if(*code != ';'){
	ctx.emit_rewind(pt);
	return NULL;
      }
      code += 1;
      goto next_statement;
    }
    ctx.emit_function_body_end();

  }
  ctx.emit_function_end();
  return code;
}

static u64 _codepoint = 0;

void debug_emit_symbol(const char * symbol){
  logd("SYMBOL: %s\n", symbol);
}

codepoint debug_emit_function_begin(){
  logd("Function begin\n");
  return ++_codepoint;
}

void debug_emit_function_end(){
  logd("FUNCTION_DEF_END\n");
}

void debug_emit_rewind(codepoint pt){
  logd("REWIND %i\n", pt);
}


codepoint debug_emit_function_body_begin(){
  logd("Function body begin\n");
  return ++_codepoint;
}

void debug_emit_function_body_end(){
  logd("FUNCTION_BODY_END\n");
}

codepoint debug_emit_funcall_begin(){
  logd("funcall begin\n");
  return ++_codepoint;
}


void debug_emit_funcall_end(){
  logd("FUNCALL END\n");
}

codepoint debug_emit_parse_type_begin(){
  logd("parse type\n");
  return ++_codepoint;
  
}

void debug_emit_parse_type_end(){
  logd("Parsed type\n");
}

typedef struct{
  u64 id;
}hydra_symbol;

typedef enum{
  HYDRA_LOAD_SYMBOL,
  HYDRA_CALL
}HYDRA_OPCODE;

typedef struct{
  hydra_symbol symbol;
  u64 size;
}hydra_type;

typedef struct{
  hydra_type type;
  hydra_symbol name;
}hydra_argument;

struct __hydra_interpreter;
typedef struct __hydra_interpreter hydra_interpreter;

typedef void (*hydra_fcn )(hydra_interpreter *);

CREATE_TABLE_DECL2(hydra_function, hydra_symbol, hydra_fcn);
CREATE_TABLE_NP(hydra_function, hydra_symbol, hydra_fcn);

CREATE_TABLE_DECL2(hydra_type, hydra_symbol, hydra_type);
CREATE_TABLE_NP(hydra_type, hydra_symbol, hydra_type);

struct __hydra_interpreter{
  void * stack;
  u64 stack_size;
  index_table * interned_strings;
  hydra_function_table * functions;
  hydra_type_table * types;
};

typedef struct{
  char data[16];

}hydra_symbol_part;

hydra_interpreter * hydra_interpreter_new(){
  hydra_interpreter interp;
  interp.stack = NULL;
  interp.stack_size = 0;
  interp.interned_strings = index_table_create(NULL, sizeof(hydra_symbol_part));
  interp.functions = hydra_function_table_create(NULL);
  interp.types = hydra_type_table_create(NULL);
  return IRON_CLONE(interp);
}

hydra_symbol hydra_intern(hydra_interpreter * interp, const char * str){
  u64 len = strlen(str);
  u64 cnt = 0;
  hydra_symbol_part * p = index_table_all(interp->interned_strings, &cnt);
  void * data = p->data;
  u64 totallen = cnt * sizeof(hydra_symbol_part);
  void * found = memmem(data, totallen, str, len + 1);
  if(found){
    return (hydra_symbol){.id = found - data};
  }
  index_table_sequence newidx = index_table_alloc_sequence(interp->interned_strings, 1 + (len + 1) / sizeof(hydra_symbol_part));
  void * target = index_table_lookup_sequence(interp->interned_strings, newidx);
  memcpy(target, str, len + 1);
  p = index_table_all(interp->interned_strings, &cnt);
  return (hydra_symbol){.id = target - (void *)p->data};
}

hydra_type hydra_locate_type(hydra_interpreter * interpreter, hydra_symbol sym){
  hydra_type type = {0};
  hydra_type_try_get(interpreter->types, sym, &type);
  return type;
}

void hydra_stack_push(hydra_interpreter * interpreter, void * data, u64 nbytes){
  interpreter->stack = ralloc(interpreter->stack, nbytes + interpreter->stack_size);
  interpreter->stack_size += nbytes;
  memcpy(interpreter->stack + interpreter->stack_size - nbytes, data, nbytes);
}

void hydra_stack_pop(hydra_interpreter * interpreter, void * dst, u64 nbytes){
  memcpy(dst, interpreter->stack + interpreter->stack_size - nbytes,  nbytes);
  interpreter->stack_size -= nbytes;
}

char * hydra_lookup_symbol(hydra_interpreter * interp, hydra_symbol sym){

  u64 cnt;
  return index_table_all(interp->interned_strings, &cnt) + sym.id;
}

hydra_fcn find_hydra_function(hydra_interpreter * interp, hydra_symbol sym){
  hydra_fcn fcn = {0};
  hydra_function_try_get(interp->functions, sym, &fcn);
  return fcn;
}

void run_bytecode(hydra_interpreter * interpreter, HYDRA_OPCODE opcode, hydra_symbol arg){
  if(opcode == HYDRA_LOAD_SYMBOL){
    hydra_stack_push(interpreter, &arg, sizeof(arg));
    logd("PUSHING: %s\n", hydra_lookup_symbol(interpreter, arg));
  }else if(opcode == HYDRA_CALL){
    void (* call) (hydra_interpreter * interpreter) = find_hydra_function(interpreter, arg);
    call(interpreter);
  }
}

void fcn_argument(hydra_interpreter * interpreter){
  hydra_symbol args[2];
  hydra_stack_pop(interpreter, args, sizeof(args));
  logd("ARGUMENT %i %i\n", args[0].id, args[1].id);
  hydra_argument arg;
  arg.name = args[1];
  arg.type = hydra_locate_type(interpreter, args[0]);
  hydra_stack_push(interpreter, &arg, sizeof(arg));
}

void fcn_begin_defun(hydra_interpreter * interp){
  hydra_symbol number_arg;
  hydra_stack_pop(interp, &number_arg, sizeof(number_arg));
  hydra_symbol name;
  hydra_stack_pop(interp, &name, sizeof(name));
  u32 count = 0;
  {
    char * str = hydra_lookup_symbol(interp, number_arg);
    
    sscanf(str, "%i", &count);
    logd("COUNT: %i %s\n", count, str);
  }

  hydra_argument args[count];
  hydra_stack_pop(interp, args, count * sizeof(hydra_argument));
  hydra_symbol return_type = {0};
  hydra_stack_pop(interp, &return_type, sizeof(return_type));
  logd("Defining function %s\n", hydra_lookup_symbol(interp, name));
  logd("Returning %s\n", hydra_lookup_symbol(interp, return_type));
  for(u32 i = 0; i < count; i++){
    logd("ARG %i: %s\n", i, hydra_lookup_symbol(interp, args[i].name));
  }
}

void fcn_end_defun(hydra_interpreter * interp){
  UNUSED(interp);
  logd("End defun\n");
}

void fcn_add(hydra_interpreter * interp){
  hydra_argument args[2];
  hydra_stack_pop(interp, args, sizeof(args));

  hydra_locate_variable(interp, args[0]);
  
}

void test_hydra(){

  hydra_interpreter * hyd = hydra_interpreter_new();
  hydra_function_set(hyd->functions, hydra_intern(hyd, "argument"), fcn_argument);
  hydra_function_set(hyd->functions, hydra_intern(hyd, "begin_defun"), fcn_begin_defun);
  hydra_function_set(hyd->functions, hydra_intern(hyd, "end_defun"), fcn_end_defun);
  hydra_function_set(hyd->functions, hydra_intern(hyd, "+"), fcn_add);


  
  hydra_type_set(hyd->types, hydra_intern(hyd, "argument"), (hydra_type){.symbol = hydra_intern(hyd, "i32"), .size = 4});
  
  ASSERT(hydra_intern(hyd, "i32").id == hydra_intern(hyd, "i32").id);
  ASSERT(hydra_intern(hyd, "i64").id == hydra_intern(hyd, "i64").id);
  ASSERT(hydra_intern(hyd, "i64").id != hydra_intern(hyd, "i32").id);
  ASSERT(hydra_intern(hyd, "2").id != hydra_intern(hyd, "i32").id);

  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "i32"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "i32"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "b"));
  run_bytecode(hyd, HYDRA_CALL, hydra_intern(hyd, "argument"));

  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "i32"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "a"));
  run_bytecode(hyd, HYDRA_CALL, hydra_intern(hyd, "argument"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "add"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "2"));

  run_bytecode(hyd, HYDRA_CALL, hydra_intern(hyd, "begin_defun"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "a"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "b"));
  run_bytecode(hyd, HYDRA_CALL, hydra_intern(hyd, "+"));
  run_bytecode(hyd, HYDRA_CALL, hydra_intern(hyd, "end_defun"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "2"));
  run_bytecode(hyd, HYDRA_LOAD_SYMBOL, hydra_intern(hyd, "4"));
  run_bytecode(hyd, HYDRA_CALL, hydra_intern(hyd, "add"));
  i32 result = 0;
  hydra_stack_pop(hyd, &result, sizeof(result));
  ASSERT(result == 6);
  
  

  
  return;
  parser_context ctx = {
    .emit_symbol = debug_emit_symbol,
    .emit_function_begin = debug_emit_function_begin,
    .emit_function_end = debug_emit_function_end,
    .emit_rewind = debug_emit_rewind,
    .emit_function_body_begin = debug_emit_function_body_begin,
    .emit_function_body_end = debug_emit_function_body_end,
    .emit_funcall_begin = debug_emit_funcall_begin,
    .emit_funcall_end = debug_emit_funcall_end,
    .emit_parse_type_begin = debug_emit_parse_type_begin,
    .emit_parse_type_end = debug_emit_parse_type_end
  };
  parse_function_def(ctx, (char *) "void myfun(x a, x b){ print(hello);\n lol(+(1, 3));}");

}
