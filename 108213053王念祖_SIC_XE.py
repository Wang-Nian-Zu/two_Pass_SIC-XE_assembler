########################################################################
# SIC XE assembler
# feature : two pass 、字面常數 (literal)  、 EQU、 Control Section 、運算式 (Expression)
#########################################################################
import sys
import json
import re

class Assembler:
    def __init__(self) : # init
        # 前面加上 __ 就是封裝，可定義私有變數或副程式
        self.__opcode = {} # 裏頭存放 opcode 的對應 format 跟 hex value
        self.instruction = [] # 儲存所有被 Scanner 分類過的指令集(指令集以 dict 表示)
        self.__pseudo_code_list = [ # 虛指令列表
            'START',
            'END',
            'BYTE',
            'WORD',
            'RESW',
            'RESB',
            'BASE',
            'CSECT',
            'EXTDEF',
            'EXTREF',
            'LTORG',
            'EQU',
        ]
        self.__extdef_table = {} # 指明哪些 symbols 在本 Control Section 中被定義，可供其他 section 引用
        self.__extref_table = {} # 指明哪些 symbols 在指明那些symbols 在本 section 會被引用，但是其他 section 中定義
        self.__symbol_table = {} # 存放多個程式區塊的 symbol table 
        self.__modified_record = {} # 存放多個程式區塊的 modified record 
        self.__literal_table = [] # 存放各種字面常數
        self.__init_optable() # 初始化 optable
        self.__error_flag = False # 紀錄程式有無報錯

    # 印出報錯資訊
    def error(self, reason):  
        if self.__error_flag == False:
            print("\n====================== Error Occur =====================\n")
        self.__error_flag = True # 紀錄程式已經有報錯
        print(f"{reason}")
    
    # 看 optable 或 pseudo_code_list 裡頭有無該 mnemonic
    def __check_mnemonic(self, mnemonic) -> bool:
        if mnemonic[0] == '+': # 如果前面有 + 號，表示 extended 格式，所以查 optable 就好
            return self.__opcode.get(mnemonic[1:]) != None
        else:
            return (self.__opcode.get(mnemonic) != None) or (mnemonic in self.__pseudo_code_list)

    # 初始化 opcode table
    def __init_optable(self) :
        with open("./opCode.txt", mode="r") as f:
            for line in f.readlines(): # 一次讀一行
                opcode_arr = list(filter(None, line.split(" "))) # filter() 函數是用於過濾掉在 line.split(" ") 中可能出現的空字串
                self.__opcode[opcode_arr[0]] = {
                    "format": opcode_arr[1].split('/'),
                    "code": int(opcode_arr[2].replace("\n", ""), base=16) # 將十六進位轉為十進位整數
                }
    #  (在 pass 2 的時候) generate object code list
    # type 就是看 n 、p 的十進位值 
    # format 就是看 x、b、p、e 的十進位值
    # offset 就是相對於 PC 或 BASE 偏移量
    def __gen_code_list(self, opcode, type, format, offset) -> list:
        # format 4
        if format & 1 == 1: # 如果 format 的最低位為1，執行相應的操作
            return [
                self.__opcode[opcode]['code'] + type,          # 第一個 byte 
                format << 4 | ((offset & 0xf0000) >> 16),      # 第二個 byte 
                (offset & 0xff00) >> 8,                        # 第三個 byte 
                offset & 0xff,                                 # 第四個 byte 
            ]
        # format 3
        else:
            return [
                self.__opcode[opcode]['code'] + type,          # 第一個 byte 
                format << 4 | ((offset & 0xf00) >> 8),         # 第二個 byte 
                offset & 0xff,                                 # 第三個 byte 
            ]

    # Scanner 讀檔並且辨別 symbol、mnemonic、operand
    def scanner(self, source_program) -> None:
        # 一個 Byte 格式的指令列表
        format1_list = ['FIX', 'FLOAT', 'HIO', 'NORM', 'SIO', 'TIO', 'CSECT', 'LTORG'] 
        # 兩個 Byte 格式的指令列表
        format2_list = ['ADDR', 'COMPR', 'DIVR', 'MULR', 'RMO', 'SHIFTL', 'SHIFTR'] 
        try: 
            with open(source_program, mode="r") as f:
                start_flag = False # 找到 START 旗幟
                end_flag = False # 找到 END 旗幟
                for index, line in enumerate(f.readlines()): # 可同時輸出索引與值
                    byte_flag = False
                    if '.' in line : # 如果此行有【.】，filter comment 
                        line = line[0:line.index('.')]# 刪除點以後的文字
                    if 'BYTE' in line and len(list(filter(None,line.replace("\t", " ").split(" ")))) > 2: # 判斷是 BYTE
                        line_list = list(filter(None,line.replace("\t", " ").split(" ")))
                        if line_list[1] == 'BYTE':
                            byte_flag = True
                        else:
                            byte_flag = False
                    if byte_flag :
                        if line_list[2][0] == 'C':
                            line_str = line.replace(" ", "").replace("\t", "").replace("\n", "")
                            if line_str[-1] != '\'':
                                self.error(f'line {index + 1}: Charactor format 需要單引號結尾')
                            if line_str.count('\'') != 2:
                                self.error(f'line {index + 1}: Charactor format 單引號過多(只能用兩個單引號將內容包住)')
                            start_pos = line.index('\'') # 會是第一個引號的位置
                            line_symbol_mnemonic = line[0:start_pos]
                            instruction_arr = list(filter(None, line_symbol_mnemonic.replace("\t", " ").split(" ")))
                            if len(instruction_arr) != 3 or instruction_arr[2] != 'C':
                                self.error(f'line {index + 1}: Charactor format error')
                            content_pos = line.index('\'') + 1
                            if line[content_pos] == '\'':
                                self.error(f'line {index+1}: Charartor can not be empty')
                            line_operand = '\'' + line[content_pos:].replace("\n", "")
                            instruction_arr[2] += line_operand
                        elif line_list[2][0] == 'X':
                            line_str = line.replace(" ", "").replace("\t", "").replace("\n", "")
                            if line_str[-1] != '\'':
                                self.error(f'line {index + 1}:BYTE hex format 需要單引號結尾')
                            if line_str.count('\'') != 2:
                                self.error(f'line {index + 1}:BYTE hex format 單引號過多(只能用兩個單引號將內容包住)')
                            start_pos = line.index('\'')
                            line_symbol_mnemonic = line[0:start_pos]
                            instruction_arr = list(filter(None, line_symbol_mnemonic.replace("\t", " ").split(" ")))
                            if len(instruction_arr) != 3 or instruction_arr[2] != 'X':
                                self.error(f'line {index + 1}:BYTE hex format error')
                            content_pos = line.index('\'') + 1
                            if line[content_pos] == '\'':
                                self.error(f'line {index+1}:BYTE hex format can not be empty')
                            # 不能有空白
                            line_operand = '\'' + line[content_pos:].replace("\n", "")
                            if " " in list(line_operand[1:].split('\''))[0] or "/t" in list(line_operand[1:].split('\''))[0]:
                                self.error(f"line {index+1}:BYTE hex content can't have space or tab charactor")
                            instruction_arr[2] += line_operand
                        else:
                            self.error(f'line {index+1}: BYTE format error')
                    elif '=C\'' in line.replace(" ", "").replace("\t", "") : # literal charactor 
                        line_str = line.replace(" ", "").replace("\t", "").replace("\n", "")
                        try:
                            if line_str[-1] != '\'':
                                self.error(f'line {index + 1}: Literal charactor format 需要單引號結尾')
                            if line_str.count('\'') != 2:
                                self.error(f'line {index + 1}: Literal charactor format 單引號過多(只能用兩個單引號將內容包住)')
                            if line_str.index('=C\'') != line_str.index('='):
                                self.error(f'line {index + 1}: Literal charactor format error')
                            start_pos = line.index('=')
                            line_symbol_mnemonic = line[0:start_pos]
                            instruction_arr = list(filter(None, line_symbol_mnemonic.replace("\t", " ").split(" ")))
                            if len(instruction_arr) > 2 or len(instruction_arr) == 0:
                                self.error(f'line {index + 1}: Literal charactor format error')
                            content_pos = line.index('\'') + 1
                            if line[content_pos] == '\'':
                                self.error(f'line {index+1}: literal charartor format can not be empty')
                            line_operand = '=C\'' + line[content_pos:].replace("\n", "")
                            instruction_arr.append(line_operand)
                        except ValueError :
                            self.error(f'line {index + 1}: Charactor format error')
                            continue
                    # literal hex format
                    elif  '=X\'' in line.replace(" ", "").replace("\t", "") :
                        line_str = line.replace(" ", "").replace("\t", "").replace("\n", "")
                        if line_str[-1] != '\'':
                            self.error(f"line {index + 1}: Literal hex format 需要單引號框住所有十六進制數字")
                        if line_str.count('\'') != 2:
                            self.error(f'line {index + 1}: Literal hex format 單引號過多(只能用兩個單引號將內容包住)')
                        if line_str.index('=')  != line_str.index('=X\''): 
                            self.error(f'line {index + 1}: literal 格式有誤')
                        start_pos = line.index('=')
                        line_symbol_mnemonic = line[0:start_pos]
                        instruction_arr = list(filter(None, line_symbol_mnemonic.replace("\t", " ").split(" ")))
                        if len(instruction_arr) > 2 or len(instruction_arr) == 0:
                            self.error(f'line {index + 1}: Literal hex format error')
                        content_pos = line.index('\'') + 1
                        if line[content_pos] == '\'':
                            self.error(f'line {index+1}: literal X format can not be empty')
                        # 不能有空白
                        line_operand = '=X\'' + line[content_pos:].replace("\n", "")
                        if " " in list(line_operand[3:].split('\''))[0] or "/t" in list(line_operand[3:].split('\''))[0]:
                            self.error(f'line {index+1}: literal X format can not have space')
                        instruction_arr.append(line_operand)        
                    elif 'EXTDEF' in line or 'EXTREF' in line: 
                        e_flag = False
                        line_str = line.split(",")
                        line_menmonic = list(filter(None,line_str[0].replace("\t"," ").replace("\n"," ").split(" ")))
                        instruction_arr = []
                        if len(line_menmonic) != 2 : # 長度一定要為二
                            self.error(f'line {index+1}: format error')
                            e_flag = True
                        else:
                            instruction_arr = line_menmonic
                        if len(instruction_arr) > 0:
                            if instruction_arr[0] != 'EXTDEF' and instruction_arr[0] != 'EXTREF':
                                self.error(f'line {index+1}: format error')
                                e_flag = True
                        if e_flag == False and len(line_str) > 1: #表示 operand 有逗號
                            for i , value in enumerate(line_str[1:]):
                                value_str = value.replace("\t","").replace(" ","")
                                if i == len(line_str[1:])-1: # 當執行到 operand 最後一個
                                    value_list = list(filter(None,value.replace("\t"," ").replace("\n"," ").split(" ")))
                                    if len(value_list) != 1:
                                        self.error(f'line {index+1}: format error')
                                        e_flag = True
                                        break
                                    else:
                                        instruction_arr.append(value_list[0])
                                elif value_str == "" or len(list(filter(None,value.replace("\t"," ").split(" ")))) > 1:
                                    self.error(f'line {index+1}: format error')
                                    e_flag = True
                                    break
                                else:
                                    instruction_arr.append(value.replace("\t","").replace(" ",""))
                        if e_flag == True:
                            continue
                    else:
                        arr_flag = False
                        for mnemonic in format2_list : # 如果他是格式二也會有","的出現，要額外處理
                            if mnemonic in line:
                                if line.count(',') > 1:
                                    self.error(f'line {index + 1}: format 2 error')
                                line = line.replace(",", " ").replace("\t", " ").replace("\n", "")
                                instruction_arr = list(filter(None, line.split(" ")))
                                arr_flag = True
                        if arr_flag == False and ',X' in line.replace("\t", "").replace(" ", ""): # 索引定址
                            # 真正是索引定址
                            line_str = line.replace("\t", "").replace("\n", "").replace(" ", "")
                            if line_str[len(line_str)-2:] != ',X':
                                self.error(f'line {index + 1}: index addressing format error')
                            elif line_str.count(',') != 1:
                                self.error(f'line {index + 1}: index addressing format error')
                            else:
                                index_pos = line.index(',')
                                line_memo = line[0:index_pos]
                                instruction_arr = list(filter(None,line_memo.replace("\t", " ").split(" ")))
                                instruction_arr.append(',X')
                                arr_flag = True
                        if arr_flag == False:
                            instruction_arr = list(filter(None, line.replace("\t", " ").replace("\n", "").split(" ")))                 
                    instruct_set = {}   # 定義 instruction format

                    if instruction_arr == [] or len(instruction_arr) == 0: # 如果該行空了就跳過
                        continue
                    # 先檢查 START 行，是否有錯誤
                    if 'START' in instruction_arr:
                        if instruction_arr.index('START') != 1 or len(instruction_arr) != 3: 
                            self.error(f'line {index + 1}: START format error ')
                            continue
                        elif len(instruction_arr[0]) > 6:
                            self.error(f'line {index + 1}: "Program name must less than 6 charactors !"')
                        start_flag = True
                    if start_flag == False :
                        continue
                    elif 'END' in instruction_arr :
                        end_flag = True
                        if instruction_arr.index('END') != 0 or len(instruction_arr) != 2: 
                            self.error(f"line {index + 1}: END format error")
                            exit(1)
                    elif '*' == instruction_arr[0] : # 後面會拿此當作 literal 在 instruction set 裡面的保留字
                         self.error(f"line {index + 1}: Symbol name can't be * (Reserved word) ")
                         continue
                    elif 'RSUB' in instruction_arr:
                        if len(instruction_arr) > 2: # RSUB 那行只有自己一個 token
                            self.error(f'line {index + 1}: RSUB format error')
                            continue
                    elif 'WORD' in instruction_arr:
                        if instruction_arr[1] != 'WORD' or len(instruction_arr) != 3 :
                            self.error(f"line {index + 1}: WORD format error")
                            continue
                    elif 'BYTE' in instruction_arr: # 檢查 BYTE 格式錯誤
                        if instruction_arr[1] == 'BYTE':
                            if (instruction_arr[2][0] == 'X') and (len(instruction_arr[2]) > 63) :
                                self.error(f"line {index + 1}: BTYE X operand's length must less than 60")   
                        else:
                            self.error(f"line {index + 1}: BTYE format error")
                            continue
                    elif 'RESW' in instruction_arr :
                        if instruction_arr.index('RESW') != 1 or len(instruction_arr) != 3 :
                            self.error(f"line {index + 1}: RESW format error")
                    elif 'RESB' in instruction_arr: 
                        if instruction_arr.index('RESB') != 1 or len(instruction_arr) != 3: 
                            self.error(f"line {index + 1}: RESB format error")
                    #  EXTDEF 用來指明哪些 symbols 在本 Control Section 中被 define
                    if 'EXTDEF' in instruction_arr:
                        if len(instruction_arr) < 2:
                            self.error(f'line {index + 1}: EXTDEF must have operand')
                            continue
                        elif instruction_arr.index('EXTDEF') != 0: # 如果 EXTDEF 不是排在第一個就報錯
                            self.error(f'line {index + 1}: EXTDEF can not have symbol')
                            continue
                        else:
                            instruct_set = {
                                'mnemonic': instruction_arr[0],
                                'operand': instruction_arr[1:],
                            }
                    # special process EXTREF
                    elif 'EXTREF' in instruction_arr:
                        if instruction_arr.index('EXTREF') != 0: # 如果 EXTREF 不是排在第一個就報錯
                            self.error(f'line {index + 1}: EXTREF can not have symbol')
                            continue
                        elif len(instruction_arr) <= 1:
                            self.error(f'line {index + 1}: EXTREF must have operand')
                            continue
                        else:
                            instruct_set = {
                                'mnemonic': instruction_arr[0],
                                'operand': instruction_arr[1:],
                            }
                    # process length = 4 (如果這一行有 4 個 token 的情況)
                    elif len(instruction_arr) == 4:
                        if self.__check_mnemonic(instruction_arr[1]) :
                            if instruction_arr[1] == 'EQU' :
                                self.error(f"line {index + 1}: EQU's operand format error")
                                instruct_set = {
                                    'symbol': instruction_arr[0],
                                    'mnemonic': instruction_arr[1],
                                    'operand': instruction_arr[2], 
                                }
                            elif instruction_arr[2][0] == '=' : # 如果 operand 開頭是 "="，表示 literal 是有空白 
                                self.error(f"line {index + 1}: literal's operand format error")
                                instruct_set = {
                                    'symbol': instruction_arr[0],
                                    'mnemonic': instruction_arr[1],
                                    'operand': instruction_arr[2], 
                                }
                            else:
                                instruct_set = {
                                    'symbol': instruction_arr[0],
                                    'mnemonic': instruction_arr[1],
                                    'operand': instruction_arr[2:], 
                                }
                        else:
                            self.error(f'line {index + 1}: nonexistent mnemonic or Operand format error')
                            continue
                    # process length = 3 (如果這一行有 3 個 token 的情況)
                    elif len(instruction_arr) == 3:
                        for mnemonic in format2_list: # 有可能是指令格式2 (2 個 byte 長度)
                            if mnemonic in instruction_arr:
                                if instruction_arr.index(mnemonic) == 0: # 該 mnemonic 前面沒有 label
                                    instruct_set = {
                                        'mnemonic': instruction_arr[0],
                                        'operand': instruction_arr[1:],
                                    }
                                    break
                                else:
                                    self.error(f'line {index + 1}: format error')
                                    continue
                        # instruct has set and continue
                        if len(instruct_set):
                            instruct_set['lineNum'] = index + 1
                            self.instruction.append(instruct_set)
                            continue

                        if ',X' in instruction_arr: # (index address mode)
                            if self.__check_mnemonic(instruction_arr[0]): # 如果第一個是助記憶碼
                                instruct_set = {
                                    'mnemonic': instruction_arr[0],
                                    'operand': instruction_arr[1:],
                                }

                        if len(instruct_set):
                            instruct_set['lineNum'] = index + 1
                            self.instruction.append(instruct_set)
                            continue
                    
                        for mnemonic in format1_list: # 如果在長度三查到 format 1
                            if mnemonic in instruction_arr:
                                if instruction_arr.index(mnemonic) == 2:
                                    self.error(f"line {index + 1}: format 1 can't have two symbol")
                                else:
                                     self.error(f"line {index + 1}: format 1 can't have operand ")
                                   
                        if self.__check_mnemonic(instruction_arr[1]):# 如果第二個是助記憶碼
                            instruct_set = {
                                'symbol': instruction_arr[0],
                                'mnemonic': instruction_arr[1],
                                'operand': instruction_arr[2],
                            }
                        else:
                            self.error(f'line {index + 1}: Nonexistent mnemonic or Operand format error')
                            continue
                    # process length = 2 (如果這一行有 2 個 token 的情況)
                    elif len(instruction_arr) == 2:
                        for mnemonic in format1_list: # 有可能是指令格式1 (1 個 byte 長度)
                            if mnemonic in instruction_arr:
                                if instruction_arr.index(mnemonic) == 1:
                                    instruct_set = {
                                        'symbol': instruction_arr[0],
                                        'mnemonic': instruction_arr[1],
                                    }
                                    break
                                else:
                                    self.error(f'line {index + 1}: format 1 must not have operand')
                                    continue
                        if 'RSUB' in instruction_arr :
                            if instruction_arr.index('RSUB') != 1:
                                self.error(f'line {index + 1}: RSUB must not have operand')
                                continue
                            else:
                                instruct_set = {
                                    'symbol': instruction_arr[0],
                                    'mnemonic': instruction_arr[1],
                                }
                        # instruct has set and continue
                        if len(instruct_set):
                            instruct_set['lineNum'] = index + 1
                            self.instruction.append(instruct_set)
                            continue
                        if instruction_arr[0] == 'EQU':
                            self.error(f'line {index + 1}: EQU must have symbol')
                            continue
                        elif self.__check_mnemonic(instruction_arr[0]): #助記憶碼在第一個參數
                            instruct_set = {
                                'mnemonic': instruction_arr[0],
                                'operand': instruction_arr[1],
                            }
                        elif self.__check_mnemonic(instruction_arr[1]): #助記憶碼在第二個參數
                            self.error(f'line {index + 1}: Operand not found')
                            instruct_set = {
                                'symbol': instruction_arr[0],
                                'mnemonic': instruction_arr[1],
                                'operand' : '1'
                            }
                        else:
                            self.error(f'line {index + 1}: nonexistent mnemonic')
                            continue
                    # process length = 1 (如果這一行有 1 個 token 的情況)
                    else: 
                        if len(instruction_arr) > 4:
                            self.error(f'line {index + 1}: 程式碼無法化成三欄式')
                            continue
                        elif self.__check_mnemonic(instruction_arr[0]):
                            for mnemonic in format1_list: # 有可能是指令格式1 (1 個 byte 長度)
                                if mnemonic in instruction_arr:
                                    instruct_set['lineNum'] = index + 1
                                    instruct_set = {
                                    'mnemonic': instruction_arr[0],
                                    }
                            if len(instruct_set):
                                instruct_set['lineNum'] = index + 1
                                self.instruction.append(instruct_set)
                                continue
                            if instruction_arr[0] == "RSUB":
                                instruct_set = {
                                    'mnemonic': instruction_arr[0],
                                }
                            else: 
                                self.error(f'line {index + 1}: operand not found')
                                continue
                        else:
                            self.error(f'line {index + 1}: Nonexistent mnemonic')
                            continue
                    instruct_set['lineNum'] = index + 1
                    self.instruction.append(instruct_set)
                if start_flag == False:
                    self.error("Error: Cannot find START instruction")
                elif end_flag  == False :
                    self.error("Error: Cannot find END instruction")
                    exit(1)
        except IOError:
            self.error('ERROR: can not found ' + source_program)
        except UnicodeDecodeError:
            self.error('ERROR: 文件中有無法解碼的字元' )
    
    def pass_one(self , inter_file) :
        cur_block = None        # 紀錄現在程式區塊
        cur_location = None     # 紀錄記憶體位址
        cur_symbol_table = {}   # 紀錄現在的 symbol table
        cur_extref_table = []   # 紀錄現在的 extref table
        start_block_name = ""
        in_file = open(inter_file , mode="w") 
        for index, instr in enumerate(self.instruction): # 把指令集依序拿出來
            if 'symbol' in instr and 'operand' in instr: # 檢查 Symbol 不能與 Operand 撞名
                if isinstance(instr['operand'], list) :
                    for oper in instr['operand']:
                        if oper == instr['symbol']:
                            self.error(f"line {instr['lineNum']} : Symbol 不能與 Operand 撞名")
                else:
                    if instr['operand'] == instr['symbol']:
                            self.error(f"line {instr['lineNum']} : Symbol 不能與 Operand 撞名")
            # 字面常數 : 如果該行有 operand 並且第一個 operand 是 "=" 開頭
            if 'operand' in instr and instr['operand'][0] == '=': 
                # 如果該 literal 沒有出現在 literal table (過濾重複的 literal)
                if instr['operand'] not in self.__literal_table: 
                    self.__literal_table.append(instr['operand']) # 將該 operand 加入 literabl table
            
            #_pseudo_code operation 找到 START 虛指令
            if instr['mnemonic'] == 'START': 
                start_block_name = instr['symbol']
                cur_block = instr['symbol']     # 更新現在位於的程式區塊
                cur_symbol_table.clear()        # reset symbol table
                cur_extref_table.clear()        # reset extref table
                self.__literal_table.clear()    # reset literal table
                self.__extdef_table.clear()     # reset extdef table
                self.__extref_table.clear()     # reset extref table
                try : 
                    cur_location = int(instr['operand'], base=16) # 將十六進位換成十進位 (location 先用十進位運算)
                except ValueError:
                    self.error(f"line {instr['lineNum']} : START's operand must be hex")
                    exit(1)
                instr['location'] = cur_location
                self.__extdef_table[cur_block] = {} # 初始化 __extdef_table 先記錄現在位於的程式區塊
            # add extdef symbol
            elif instr['mnemonic'] == 'EXTDEF': # 虛指令不算記憶體位置
                for ext_def in instr['operand']: # 將 external defination's operand 都拿出來
                    self.__extdef_table[cur_block][ext_def] = None # 初始化這些定義給外部使用的參數
            # add extref symbol
            elif instr['mnemonic'] == 'EXTREF': # 虛指令不算記憶體位置
                cur_extref_table += instr['operand'] # list 相加
            # declare variable
            elif instr['mnemonic'] == 'RESW':
                # 先紀錄該指令行的 location counter
                instr['location'] = cur_location 
                try : 
                    cur_location += int(instr['operand']) * 3 # location counter 加上 operand 值乘 3
                except(ValueError,TypeError):
                    self.error(f"line {instr['lineNum']} : RESW's operand has wrong data type ")
                except KeyError:
                    self.error(f"line {instr['lineNum']}")
            elif instr['mnemonic'] == 'RESB': 
                # 先紀錄該指令行的 location counter
                instr['location'] = cur_location 
                try : 
                    cur_location += int(instr['operand']) # location counter 加上 operand
                except(ValueError,TypeError):
                    self.error(f"line {instr['lineNum']} : RESB's operand has wrong data type ")
                except KeyError:
                    pass
            # clear literal
            elif instr['mnemonic'] == 'LTORG' or instr['mnemonic'] == 'END': # 當遇到 LTORG 語句或程式結束
                it = index  # 是目前的索引值 ，紀錄下一個 literal position
                for literal in self.__literal_table:
                    it += 1
                    # 將 literal 加入 symbol table
                    cur_symbol_table[literal] = cur_location 
                    # add new instruction at next one
                    self.instruction.insert(it, {
                        'symbol': '*',
                        'mnemonic': literal,
                        'location': cur_location
                    })
                    # compute memory displacement
                    if literal[1] == 'C': 
                        # charactor =C'HELLO'
                        # \' 字串中表示一个單引號字元， list() => [ 'HELLO' , '']
                        if len(list(literal[3:].split('\''))[0]) > 30 :
                            self.error(f"line {instr['lineNum']} :literal C format must less than 30 charactors")
                        else:
                            cur_location += len(list(literal[3:].split('\''))[0]) 
                    elif literal[1] == 'X':  # hex =X'1F'
                        if len(list(literal[3:].split('\''))[0]) % 2 != 0 :
                            self.error(f"line {instr['lineNum']} : literal X format content must be even")
                        elif len(list(literal[3:].split('\''))[0]) == 0 :
                            self.error(f"line {instr['lineNum']} : literal X format content can't be empty")
                        elif len(list(literal[3:].split('\''))[0]) > 60:
                            self.error(f"line {instr['lineNum']} : literal X format operand length must less than 60")
                        else:
                            # // 除 2 向下取整數，因為十六進位是兩個數代表一個 Byte
                            cur_location += len(list(literal[3:].split('\''))[0]) // 2
                    else:
                        self.error(f"line {instr['lineNum']} : literal format error")
                self.__literal_table.clear()
                # update symbol table 、 extref_table
                if instr['mnemonic'] == 'END':
                    # [notice]: must use copy before reset
                    self.__symbol_table[cur_block] = cur_symbol_table.copy() # 將此 symbol table 放入該控制區塊的 symbol table
                    self.__extref_table[cur_block] = cur_extref_table.copy() # 將此 extref table 放入該控制區塊的 extref table
                    cur_symbol_table.clear()
                    cur_extref_table.clear()
                    self.__literal_table.clear()
                    if instr['operand'] not in self.__symbol_table[start_block_name] :
                        self.error(f"line {instr['lineNum']} : END's operand is undefined in symbol table ")
            # reset and use new block
            elif instr['mnemonic'] == 'CSECT': # 遇到 control section 虛指令 
                cur_location = 0 # location counter 重新計算
                instr['location'] = cur_location
                # [notice]: must use copy before reset
                self.__symbol_table[cur_block] = cur_symbol_table.copy()
                self.__extref_table[cur_block] = cur_extref_table.copy()
                try:
                    cur_block = instr['symbol'] # 將現在的控制區塊換成該 symbol 名稱
                    self.__extdef_table[cur_block] = {}
                    self.__extref_table[cur_block] = []
                except KeyError : # 可能找不到 symbol 
                    self.error(f"line {instr['lineNum']} : CSECT must have a symbol")
                    exit(1) # 暫停
                cur_symbol_table.clear()
                cur_extref_table.clear()
            # define memory position
            elif instr['mnemonic'] == 'EQU':
                if instr['operand'] == '*': # 如果 operand 是給星號
                    instr['location'] = cur_location # 就是紀錄現在位址
                
            elif instr['mnemonic'] == 'BYTE':
                instr['location'] = cur_location
                # uncertain the number of byte, must be calculated first
                if instr['operand'][0] == 'X': # hex : X'1F'，兩個是一個 Byte
                    cur_location += len(list(instr['operand'][2:].split('\''))[0]) // 2
                elif instr['operand'][0] == 'C': # charactor : C'HELLO'
                    if len(list(instr['operand'][2:].split('\''))[0]) > 30 :
                        self.error(f"line {instr['lineNum']} : BYTE's C format must less than 30 charactors")
                    else:
                        cur_location += len(list(instr['operand'][2:].split('\''))[0])
                else:
                    self.error(f"line {instr['lineNum']} : BYTE's operand format error")
            elif instr['mnemonic'] == 'WORD':
                instr['location'] = cur_location
                cur_location += 3 # WORD length must be equal to 3
            # 格式 4 ( 4 個 bytes )
            elif instr['mnemonic'][0] == '+': 
                instr['location'] = cur_location
                cur_location += 4 # 位置要加 4 
            else:
                # skip added literal instruction and BASE
                if 'symbol' in instr and instr['symbol'] == '*' or instr['mnemonic'] == 'BASE':
                    pass
                else:
                    instr['location'] = cur_location
                    # 取 opcode 值時，如果有 + 在前頭就要忽略
                    opcode = instr['mnemonic'][1:] if instr['mnemonic'][0] == '+' else instr['mnemonic']
                    # 查 opcode table 看自己是格式多少，就加上多少長度 
                    # format 1
                    if self.__opcode[opcode]['format'][0] == '1':
                        cur_location += 1
                    # format 2
                    elif self.__opcode[opcode]['format'][0] == '2':
                        cur_location += 2
                    # Format 3
                    else:
                        cur_location += 3
            
            # calculate EQU with symbol
            if instr['mnemonic'] == 'EQU':
                # add literal in symbol table
                if instr['operand'] == '*': # 如果 value 是 *
                    cur_symbol_table[instr['symbol']] = instr['location'] # 就直接將該 symbol 對應 現在的位置
                elif (len(re.split(r'[+-]' , instr['operand'])) >= 3):
                    self.error(f"line {instr['lineNum']} : This assembler's expressions can't calculate three operand")
                    continue
                elif '-' in instr['operand']:
                    symbol_1, symbol_2 = instr['operand'].split('-') # 用"-"分開兩個 symbol
                    try:
                        cur_symbol_table[instr['symbol']] = cur_symbol_table[symbol_1] - cur_symbol_table[symbol_2]
                    except KeyError:
                        self.error(f"line {instr['lineNum']} : Operand's symbol is undefined")
                elif '+' in instr['operand']:
                    symbol_1, symbol_2 = instr['operand'].split('+') # 用"+"分開兩個 symbol
                    try:
                        cur_symbol_table[instr['symbol']] = cur_symbol_table[symbol_1] + cur_symbol_table[symbol_2]
                    except KeyError:
                        self.error(f"line {instr['lineNum']} : Operand's symbol is undefined")
                else:
                    try : # EQU 相等於十進位數字
                        cur_symbol_table[instr['symbol']] = int(instr['operand'])
                    except ValueError: # EQU 相等於單一個 symbol
                        location = cur_symbol_table[instr['operand']] if instr['operand'] in cur_symbol_table else 0
                        if location == 0:
                            self.error(f"line {instr['lineNum']} : EQU's operand is undefined (no forward reference)")
            # add other symbol in symbol table
            elif 'symbol' in instr and instr['symbol'] != '*':
                if cur_symbol_table.get(instr['symbol']) == None:
                    if self.__check_mnemonic(instr['symbol']):
                        self.error(f"line {instr['lineNum']} : symbol 不能與保留字同名")
                    cur_symbol_table[instr['symbol']] = instr['location']
                else:
                    self.error(f"line {instr['lineNum']} : duplicate symbol")
            if 'symbol' in instr:
                if instr['symbol'] in self.__extdef_table[cur_block]: # 如果該 symbol 有出現在 external defination table
                    try:
                        self.__extdef_table[cur_block][instr['symbol']] = instr['location']
                    except KeyError:
                        self.error(f"line {instr['lineNum']} : {instr['symbol']} 找不到 location ")
            # 將該行指令集寫入中間檔
            in_file.write(json.dumps(self.instruction[index]) + '\n')     
        in_file.close()     
       
    # pass two
    def pass_two(self):
        b_loc = None            # 紀錄 register BASE
        cur_block = None        # 標示現在的程式區塊
        cur_modified_list = []  # 紀錄現在程式區塊的 M records
        skip_instr = [ 'LTORG', 'RESW', 'RESB', 'EQU',] # 虛指令沒有 object code
        start_location = 0
        for index, instr in enumerate(self.instruction): # 把指令集依序拿出來
            if instr['mnemonic'] in skip_instr: # 如果是在虛指令列表，直接跳過
                continue
            elif instr['mnemonic'] == 'EXTDEF': # 檢查 EXTDEF
                if self.__extdef_table[cur_block] != {}:
                    for label, value in self.__extdef_table[cur_block].items():
                        if value == None:
                            self.error(f"line {instr['lineNum']} : {cur_block} 程式區塊中 EXTDEF 找不到 {label} 的 location") 
            elif instr['mnemonic'] == 'EXTREF': # 檢查 EXTREF
                for ref_symbol in self.__extref_table[cur_block]:
                    find_it = False
                    if self.__extdef_table.get(ref_symbol) != None:
                        find_it = True
                    else:
                        for block_name , dict in self.__extdef_table.items():
                            if dict.get(ref_symbol) != None and block_name != cur_block:
                                find_it = True
                                break
                    if find_it == False:
                        self.error(f"line {instr['lineNum']} : EXTREF have an {ref_symbol} undefined symbol")

            elif instr['mnemonic'] == 'START':
                # 更新現在的程式區塊
                cur_block = instr['symbol']  
                # 初始化現在的 modified_list
                cur_modified_list = [] 
                start_block_name = instr['symbol']  
                start_location = instr['location']  
            elif instr['mnemonic'] == 'END':
                # 將現在的 modified_list 紀錄到 modified_record 
                self.__modified_record[cur_block] = cur_modified_list.copy() 
                # 清掉現在 modified_list
                cur_modified_list.clear() 
            elif instr['mnemonic'] == 'CSECT': # control section
                # 將現在的 modified_list 紀錄到 modified_record 
                self.__modified_record[cur_block] = cur_modified_list.copy()
                # 清掉現在 modified_list
                cur_modified_list.clear()
                # 更新現在的程式區塊
                cur_block = instr['symbol']
            # update B register content
            elif instr['mnemonic'] == 'BASE':
                try:
                    base_operand = instr['operand']
                except KeyError:
                    self.error(f"line {instr['lineNum']} : BASE must have a operand")
                try:
                    b_loc = self.__symbol_table[cur_block][base_operand]
                except KeyError:
                    self.error(f"line {instr['lineNum']} : BASE's operand is not defined in symbol table")

            # literal instruction
            elif instr['mnemonic'][0] == '=': 
                data = list(instr['mnemonic'][3:].split('\''))[0]
                if instr['mnemonic'][1] == 'C':
                    objcode = []
                    for c in data:
                        objcode.append(ord(c)) # 將 charactor 取得 ASCII 碼後放入 object code list
                    instr['objcode'] = objcode 
                elif instr['mnemonic'][1] == 'X':
                    
                    objcode = []
                    for i in range(0, len(data), 2): # 兩個兩個一組
                        try:
                            objcode.append(int(data[i : i + 2], base=16)) # 字串轉成十六進位整數存入 object code list
                        except ValueError:
                            self.error(f"line {index + 1} : invalid literal with base 16 ")
                            break
                    instr['objcode'] = objcode
            elif instr['mnemonic'] == 'WORD':
                if (len(re.split(r'[+-]' , instr['operand'])) >= 3):
                    self.error(f"line {instr['lineNum']} : This assembler's expressions can't calculate three operand")
                    continue
                if '-' in instr['operand']:
                    symbol_1, symbol_2 = instr['operand'].split('-')
                    # 查看 symbol table 有沒有該 symbol1 的 location ， 如果有就取出，如果沒有先回傳 0
                    location_1 = self.__symbol_table[cur_block][symbol_1] \
                        if symbol_1 in self.__symbol_table[cur_block] else 0
                    if location_1 == 0: # 如果該位置是 0，表示此 symbol 還沒有定義在 symbol table 中
                        if symbol_1 in self.__extref_table[cur_block] :
                            # 寫一個 M records ，紀錄該指令位址，word 是 6 個 half Byte
                            cur_modified_list.append({
                                'location': instr['location'] - start_location,
                                'byte': 6,
                                'offset': '+' + symbol_1,
                            })
                        else:
                            self.error(f"line {instr['lineNum']} : {symbol_1} is undefined (reference?)")
                    # 查看 symbol table 有沒有該 symbol2 的 location ， 如果有就取出，如果沒有先回傳 0
                    location_2 = self.__symbol_table[cur_block][symbol_2] \
                        if symbol_2 in self.__symbol_table[cur_block] else 0
                    if location_2 == 0:
                        if symbol_2 in self.__extref_table[cur_block] :
                            # 寫一個 M records ，紀錄該指令位址，word 是 6 個 half Byte，注意要用減號
                            cur_modified_list.append({
                                'location': instr['location'] - start_location,
                                'byte': 6,
                                'offset': '-' + symbol_2,
                            })
                        else:
                            self.error(f"line {instr['lineNum']} : {symbol_2} is undefined (reference?)")
                    # 計算 word 的 object code
                    instr['objcode'] = [
                        ((location_1 - location_2) & (0xff << i)) >> i
                        for i in range(16, -1, -8)
                    ]
                elif '+' in instr['operand']:
                    symbol_1, symbol_2 = instr['operand'].split('+')
                    # 查看 symbol table 有沒有該 symbol1 的 location ， 如果有就取出，如果沒有先回傳 0
                    location_1 = self.__symbol_table[cur_block][symbol_1] \
                        if symbol_1 in self.__symbol_table[cur_block] else 0
                    if location_1 == 0:
                        if symbol_1 in self.__extref_table[cur_block] :
                            # 寫一個 M records ，紀錄該指令位址，word 是 6 個 half Byte
                            cur_modified_list.append({
                                'location': instr['location'] - start_location,
                                'byte': 6,
                                'offset': '+' + symbol_1,
                            })
                        else:
                            self.error(f"line {instr['lineNum']} : {symbol_1} is undefined (reference?)")
                    # 查看 symbol table 有沒有該 symbol2 的 location ， 如果有就取出，如果沒有先回傳 0
                    location_2 = self.__symbol_table[cur_block][symbol_2] \
                        if symbol_2 in self.__symbol_table[cur_block] else 0
                    if location_2 == 0:
                        if symbol_2 in self.__extref_table[cur_block] :
                            # 寫一個 M records ，紀錄該指令位址，word 是 6 個 half Byte
                            cur_modified_list.append({
                                'location': instr['location'] - start_location,
                                'byte': 6,
                                'offset': '+' + symbol_2,
                            })
                        else:
                            self.error(f"line {instr['lineNum']} : {symbol_2} is undefined (reference?)")
                    instr['objcode'] = [
                        ((location_1 + location_2) & (0xff << i)) >> i
                        for i in range(16, -1, -8)
                    ]
                else: 
                    try :
                        if int(instr['operand']) > 16777215 : 
                            self.error(f"line {index + 1} : DATA's operand exceed 0xFFFFFF")
                        # 處理 operand 是普通十進位整數的情形
                        # 以下是為了後續將 list 中的每一個元素(十進位數字)當成一個 btye (十六進位) 去處理
                        instr['objcode'] = [ (int(instr['operand']) & (0xff << i)) >> i
                            for i in range(16, -1, -8) ]
                    except ValueError: # 處理單一 symbol 
                        symbol_1 = instr['operand']
                        location = self.__symbol_table[cur_block][symbol_1] if symbol_1 in self.__symbol_table[cur_block] else 0
                        if location == 0:
                            if symbol_1 in self.__extref_table[cur_block] :
                                # 寫一個 M records ，紀錄該指令位址，word 是 6 個 half Byte
                                cur_modified_list.append({
                                    'location': instr['location'] - start_location,
                                    'byte': 6,
                                    'offset': '+' + symbol_1,
                                })
                            else:
                                self.error(f"line {instr['lineNum']} : {symbol_1} is undefined (reference?)")
                        instr['objcode'] = [
                            ((location) & (0xff << i)) >> i
                            for i in range(16, -1, -8)
                        ]   
            elif instr['mnemonic'] == 'BYTE':
                data = list(instr['operand'][2:].split('\''))[0]
                if instr['operand'][0] == 'C':
                    objcode = []
                    for c in data:
                        objcode.append(ord(c))
                    instr['objcode'] = objcode
                elif instr['operand'][0] == 'X':
                    if (len(data) % 2) != 0:
                        self.error(f"line {instr['lineNum']} : BYTE's X format must be even")
                    objcode = []
                    for i in range(0, len(data), 2):
                        try:
                            objcode.append(int(data[i : i + 2], base=16)) # 十六進位轉十進位
                        except ValueError:
                            self.error(f"line {index + 1} : BYTE's X operand must be base 16")
                            break
                    instr['objcode'] = objcode
            else:
                # register coresponding code
                register_cord = {'A': 0, 'X': 1, 'L': 2, 'B': 3, 'S': 4, 'T': 5, 'F': 6,}
                # format 2
                format2_list = ['ADDR', 'CLEAR', 'COMPR', 'DIVR', 'MULR', 'RMO','SHIFTL', 'SHIFTR', 'SVC', 'TIXR']
                format2_oper_1_list = ['ADDR', 'CLEAR', 'SVC', 'TIXR']
                format2_oper_2_list = ['COMPR', 'DIVR', 'MULR', 'RMO', 'SHIFTL', 'SHIFTR',]
                for mnemonic in format2_list:
                    if instr['mnemonic'] == mnemonic:
                        if len(instr['operand']) == 2: # 2 個 operand
                            if instr['mnemonic'] in format2_oper_1_list:
                                self.error(f"line  {instr['lineNum']} : This format2 instruction must be one operand")
                                instr['objcode'] = [self.__opcode[mnemonic]['code'],-1]
                            elif instr['mnemonic'] == 'SHIFTL' or instr['mnemonic'] == 'SHIFTR':
                                if register_cord.get(instr['operand'][0])== None:
                                    self.error(f"lin {instr['lineNum']} : undefined register coresponding code")
                                    instr['objcode'] = [self.__opcode[mnemonic]['code'],-1]
                                else:
                                    instr['objcode'] = [
                                        self.__opcode[mnemonic]['code'],    # 第一個 Byte
                                        register_cord[instr['operand'][0]] << 4  # 第二個 Byte 
                                    ]
                            elif(register_cord.get(instr['operand'][0])== None) or (register_cord.get(instr['operand'][1]) == None) :
                                self.error(f"line {instr['lineNum']} : undefined register coresponding code")
                                instr['objcode'] = [self.__opcode[mnemonic]['code'],-1]
                            else:
                                # << 4 也可以說是 十進位 乘 16 
                                instr['objcode'] = [
                                    self.__opcode[mnemonic]['code'],    # 第一個 Byte
                                    register_cord[instr['operand'][0]] << 4 | register_cord[instr['operand'][1]] # 第二個 Byte 
                                ]
                        elif len(instr['operand']) == 1: # 1 個 operand
                            if instr['mnemonic'] in format2_oper_2_list:
                                self.error(f"line {instr['lineNum']} : This format2 instruction must have two operands")
                                instr['objcode'] = [self.__opcode[mnemonic]['code'],-1]
                            elif register_cord.get(instr['operand'][0])== None :
                                self.error(f"line {instr['lineNum']} : undefined register coresponding code")
                                instr['objcode'] = [self.__opcode[mnemonic]['code'],-1]
                            else: 
                                instr['objcode'] = [
                                    self.__opcode[mnemonic]['code'],          # 第一個 Byte 
                                    register_cord[instr['operand'][0]] << 4   # 第二個 Byte 
                                ]
                if 'objcode' in instr: # 如果已經有 object code 就可以往下一個 instruction 走
                    continue
                elif instr['mnemonic'] == 'RSUB':
                    # type = 3 因為 n = 1，p = 1 的關係
                    instr['objcode'] = self.__gen_code_list('RSUB', 3, 0, 0)
                else:
                    # < immediate format (n: 0, i: 1) 立即定址 >==================================================
                    if instr['operand'][0] == '#':  # 不需要 modification record
                        token = instr['operand'][1:]
                        # 當 operand is symbol
                        if token in self.__symbol_table[cur_block]: 
                            symbol_loc = self.__symbol_table[cur_block][token]
                            offset = symbol_loc - instr['location'] - 3 # 減三是因為要減掉 program counter
                            # format 3 (先用 PC 檢查是否超過)
                            if offset >= -2048 and offset <= 2047:
                                # type = 1 因為 n = 0，i = 1 的關係，format = 2，原因是 x = 0 b = 0 p = 1 e= 0 的關係
                                instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 1, 2, offset)
                            else: # 不再該範圍就需要用到 base register 
                                offset = symbol_loc - b_loc
                                # format 3 
                                if offset >= 0 and offset <= 4095:
                                    # type = 1 因為 n = 0，i = 1的關係，format = 4，原因是 x = 0 b = 1 p = 0 e= 0 的關係
                                    instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 1, 4, offset)
                                # format 4
                                else:
                                    # type = 1 因為 n = 0，i = 1 的關係，format = 4，原因是 x = 0 b = 0 p = 0 e= 1 的關係，直接放 location 位址
                                    instr['objcode'] = self.__gen_code_list(instr['mnemonic'][1:], 1, 1, symbol_loc)
                        # 當 operand is number
                        else:
                            # this does not memory, so do not consider PC and B
                            offset = int(token)
                            # format 4 ， type = 1 因為 n = 0，i = 1 的關係，format = 1，原因是 x = 0 b = 0 p = 0 e= 1 的關係
                            if offset > 4095:
                                instr['objcode'] = self.__gen_code_list(instr['mnemonic'][1:], 1, 1, offset)
                            # format 3，type = 1 因為 n = 0，i = 1 的關係，format = 1，原因是 x = 0 b = 0 p = 0 e= 0 的關係
                            else:
                                instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 1, 0, offset)
                    # < indirect format (n: 1, i: 0) 間接定址 > ===================================================
                    elif instr['operand'][0] == '@':
                        symbol = instr['operand'][1:]
                        # 查找 symbol table 中該 symbol 的 location，如果沒有就回傳 None 
                        symbol_loc = self.__symbol_table[cur_block][symbol] \
                            if symbol in self.__symbol_table[cur_block] else None
                        # symbol not defined
                        if symbol_loc == None:
                            self.error(f"line {instr['lineNum']}: symbol hasn't been defined")
                        else:
                            # calculate offset
                            offset = symbol_loc - instr['location'] - 3 # 減三是因為要減掉 program counter
                            # format 3 (PC) ， type = 2 因為 n = 1，i = 0 的關係，format = 2，原因是 x = 0 b = 0 p = 1 e= 0 的關係
                            if offset >= -2048 and offset <= 2047:
                                instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 2, 2, offset)
                            else:
                                offset = symbol_loc - b_loc
                                # format 3 (Base)，type = 2 因為 n = 1，i = 0 的關係，format = 4，原因是 x = 0 b = 1 p = 0 e= 0 的關係
                                if offset >= 0 and offset <= 4095:
                                    instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 2, 4, offset)
                                # format 4，type = 2 因為 n = 1，i = 0 的關係，format = 1，原因是 x = 0 b = 0 p = 0 e= 1 的關係，直接放 location 位址
                                else:
                                    instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 2, 1, symbol_loc)
                    # < direct format (n: 1, i: 1) 直接地址 > =================================================
                    # 需要寫 M record
                    else:
                        format_num = 0  # x, b, p, e 加起來的十進位數字
                        # 如果 operand 是一個 list 型態，並且其中有 X 存在
                        if isinstance(instr['operand'], list) and ',X' in instr['operand']: 
                            if instr['operand'].index(',X') == 1:
                                format_num |= 8 # 表示 x = 1 所以要加 8
                            else:
                                self.error(f"line {instr['lineNum']}: Operand format error")
                        # format 4
                        if instr['mnemonic'][0] == '+':
                            format_num |= 1 # 表示 e = 1 所以要加 1
                            symbol_loc = None
                            mnemonic = instr['mnemonic'][1:] # 把 + 忽略劉後面的 mnemonic
                            if isinstance(instr['operand'], list):
                                if format_num == 9:
                                    first_element = instr['operand'][0]
                                else:
                                    self.error(f"line {instr['lineNum']}: Operand format error")
                            else: 
                                first_element = instr['operand']
                            try: # get symbol location ， 找出第一個 operand 在 symbol table 的 location
                                symbol_loc = self.__symbol_table[cur_block][first_element]
                            except KeyError:
                                symbol_loc = None
                            # symbol nodefined (EXTREF)
                            if symbol_loc == None: # 如果在該區塊的 symbol table 找不到，有可能是外部引用或還未定義
                                # by default, EXTREF memory reference is 0
                                # type = 3 => 因為 n=1、i=1
                                instr['objcode'] = self.__gen_code_list(mnemonic, 3, format_num, 0)
                                if first_element in self.__extref_table[cur_block]:
                                    # 加入 M record ， location 要跳過 1 個 byte，然後修正 5 個 half-byte
                                    cur_modified_list.append({
                                        'location': instr['location'] + 1 - start_location,
                                        'byte': 5,
                                        'offset': '+' + first_element,
                                    })
                                else:
                                    self.error(f"line {instr['lineNum']} : {first_element} is undefined (reference?)")
                            else:
                                # type = 3 因為 n=1、i=1
                                instr['objcode'] = self.__gen_code_list(mnemonic, 3, format_num, symbol_loc)
                                # 加入 M record ， location 要跳過 1 個 byte，然後修正 5 個 half-byte
                                cur_modified_list.append({
                                    'location': instr['location'] + 1 - start_location,
                                    'byte': 5,
                                    'offset': '',
                                })
                        # format 3
                        else: 
                            symbol_loc = None
                            # get first element
                            if isinstance(instr['operand'], list):
                                if format_num == 8:
                                    first_element = instr['operand'][0] 
                                else:
                                    self.error(f"line {instr['lineNum']}: Operand format error")
                            else :
                                first_element = instr['operand']
                            # get symbol location
                            try:
                                symbol_loc = self.__symbol_table[cur_block][first_element]
                            except KeyError:
                                symbol_loc = None
                            # symbol nodefined (EXTREF)
                            if symbol_loc == None:
                                instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 3, format_num, 0)
                                self.error(f"line {instr['lineNum']} : Operand's symbol is undefined or Not found ")
                            else:
                                offset = symbol_loc - instr['location'] - 3 # 先相對於 PC 
                                # format 3 (PC)
                                if offset >= -2048 and offset <= 2047:
                                    format_num |= 2 # p = 1 ，所以要加 2
                                    instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 3, format_num, offset)
                                # format 3 (Base)
                                else:
                                    format_num |= 4 # b = 1 ，所以要加 4
                                    offset = symbol_loc - b_loc
                                    instr['objcode'] = self.__gen_code_list(instr['mnemonic'], 3, format_num, offset)
        
    def write_object_program(self, file_name) -> None :
        # record program block length and start position
        cur_block = {} # 紀錄現在的程式區塊
        cur_objcode_list = [] # 紀錄現在的 object code list (每一個元素都是一行 T record 的所有 object code)
        cur_position_list = [] # 紀錄程式區塊的起始位置與長度 (每一個元素都是一行 T record 的起始位址)
        program_info = {} # 整體程式的資訊
        end_position = () # 以 tuple 型態儲存
        # 如果遇到'RESW', 'RESB'可能會有記憶體不連續，需要設定一個新的 T record

        def gen_extref_str(ext_info: list) -> str: # R record
            ext_str = 'R '
            for label in ext_info:
                ext_str += '{:<6s} '.format(label)
            return ext_str.strip()

        def gen_extdef_str(ext_info: dict) -> str: # D record
            ext_str = 'D '
            for label, value in ext_info.items():  
                ext_str += '{:<6s} {:06X} '.format(label, value)
            return ext_str.strip()

        def gen_modified_list(modified_info: list) -> list: # M record
            modified_list = []
            for info in modified_info:
                modified_str = 'M {:06X} {:02X} {:<7s}'.format(info['location'], info['byte'], info['offset'])
                modified_list.append(modified_str.strip())
            return modified_list

        def gen_block_info(symbol_info: dict) -> dict:
            block_info = {
                'name': symbol_info['symbol'], # 程式區塊名稱
                'length': 0,                   # 程式區塊總長度
                'start': instr['location'],    # 程式區塊起始位址
            }
            extdef_info = self.__extdef_table[symbol_info['symbol']]
            if extdef_info: # 如果此程式區塊有外部定義的資訊
                block_info['extdef'] = gen_extdef_str(extdef_info)
            else:
                block_info['extdef'] = ''

            extref_info = self.__extref_table[symbol_info['symbol']]
            if extref_info: # 如果此程式區塊有外部參考的資訊
                block_info['extref'] = gen_extref_str(extref_info)
            else:
                block_info['extref'] = ''

            modified_info = self.__modified_record[symbol_info['symbol']]
            if modified_info: # 如果此程式區塊有 M record 的資訊
                block_info['modified'] = gen_modified_list(modified_info)
            else:
                block_info['modified'] = []

            return block_info 
        # write_file 主程式 ==============================================================
        for instr in self.instruction: # 將指令集依序取出
            # 遇到要重新開啟另一行 T record 的虛指令
            if instr['mnemonic'] == 'RESW' or instr['mnemonic'] == 'RESB' : 
                if cur_objcode_list[-1] == '': # 上一個可能也是遇到不連續記憶體位址的虛指令
                    if instr.get('location') != None:
                        cur_position_list[-1] = instr['location']
                else : # 上一個是連續記憶體位址指令，而這個是第一次遇到不連續記憶體位址的虛指令
                    if instr.get('location') == None:
                        cur_position_list.append('')
                    else: 
                        cur_position_list.append(instr['location'])
                    cur_objcode_list.append('')
            
            if instr['mnemonic'] == 'START':
                cur_objcode_list.clear() # 初始化 object code list 
                cur_position_list.clear() # 初始化 存現在程式區塊每一個 t record 的起始區塊
                cur_block = gen_block_info(instr)  

            elif instr['mnemonic'] == 'CSECT': # 如果遇到 Control Section
                name = cur_block['name'] # 程式區塊名稱
                del cur_block['name'] # 用來刪除 cur_block 裡頭的 name 物件 (因為他已經當作 key 使用)
                program_info[name] = cur_block # 記錄前一個程式區塊的資訊
                
                # merge this block object code
                program_info[name]['objcode'] = {} 
                for index, pos in enumerate(cur_position_list):
                    program_info[name]['objcode'][pos] = cur_objcode_list[index]
                
                # define new block info
                cur_objcode_list.clear()
                cur_position_list.clear()
                cur_block = gen_block_info(instr)
            elif instr['mnemonic'] == 'END': 
                name = cur_block['name'] # 紀錄現在程式區塊名稱
                del cur_block['name'] # 用來刪除 cur_block 裡頭的 name 物件 (因為他要當作 key 使用)
                program_info[name] = cur_block # 以現在程式區塊名稱作為 Key 儲存現在程式區塊的相關資訊

                # merge this block object code
                program_info[name]['objcode'] = {}
                for index, pos in enumerate(cur_position_list):
                    program_info[name]['objcode'][pos] = cur_objcode_list[index]

                # END symbol will record start code position
                for block in self.__symbol_table.keys(): # 遍歷程式中的所有區塊名稱
                    if instr['operand'] in self.__symbol_table[block]: # 如果起始 symbol 名稱在該程式區塊中
                        end_position = (block, self.__symbol_table[block][instr['operand']]) # 紀錄程式區塊名稱 以及該起始 symbol 的位址
                if len(end_position) == 0:
                    self.error(f"line {instr['lineNum']}: END's operand isn't defined in symbol table")
                    exit(1)
            elif 'location' in instr: # 如果該行指令集有 location
                length = instr['location'] # 長度改成現在的 location
                if 'objcode' in instr: # 如果該行指令集有 object code 
                    length += len(instr['objcode']) # 加上四種不同長度格式
                cur_block['length'] = max(cur_block['length'], length) # 現在的程式區塊長度 跟 新算出的 length 取最大值，成為現在新的程式區塊長度
            if 'objcode' in instr: # 如果該行指令集有 object code
                objcode_str = ''
                for opc in instr['objcode']: # 將 object code list 依序輸出
                    objcode_str += '{:02X}'.format(opc) # 以兩位的十六進制大寫字母形式進行格式化輸出
                instr['objcode'] = objcode_str # 新格式存入 指令集 的 objcode 
                if len(cur_objcode_list):
                    now_obj_list = cur_objcode_list[-1].split(' ') # 去除 object code 之間的空白格，為了算長度
                    obj_len = ''
                    for obj_str in now_obj_list:
                        obj_len += obj_str
                    if len(obj_len) + len(objcode_str) > 60: # 超過 30 byte 要換一個 T record
                        cur_position_list.append(instr['location'])
                        cur_objcode_list.append(objcode_str+' ')
                    else:
                        if cur_objcode_list[-1] == '': # 如果上一個是要重新寫 T record 的虛指令
                            cur_position_list[-1] = instr['location'] # 更新 location 為此指令當開頭
                        cur_objcode_list[-1] += objcode_str+' '
                else:
                    cur_position_list.append(instr['location'])
                    cur_objcode_list.append(objcode_str+' ')

        with open(file_name, mode = 'w') as f: # 打開輸出檔案
            for symbol, info in program_info.items(): # item 可以遍歷所有 (鍵,值) 
                # header
                f.write('H {:<6s} {:06X} {:06X}\n'.format(
                    symbol, info['start'], info['length']
                ))
                print('\nH {:<6s} {:06X} {:06X}'.format(
                    symbol, info['start'], info['length']
                ))

                # external define
                if info['extdef']:
                    f.write(info['extdef'] + '\n')
                    print(info['extdef'])
                
                # external reference
                if info['extref']:
                    f.write(info['extref'] + '\n')
                    print(info['extref'])

                # T record
                for offset, content in info['objcode'].items(): # item 可以遍歷所有 (鍵,值) 
                    # offset : 相對於起始的偏移值
                    # content : 該行所有的 object code
                    if (content == ''): # 因為上面為了分行 T record，可能會有 '' (空字串) 的問題
                        continue
                    else:
                        # 去除 object code 之間的空白格，為了算長度
                        content_list = content.split(' ')
                        content_len = ''
                        for content_str in content_list:
                            content_len += content_str
                        ##########################################
                        f.write('T {:06X} {:02X} {}\n'.format(offset, len(content_len) // 2, content))
                        print('T {:06X} {:02X} {}'.format(offset, len(content_len) // 2, content))

                # modified record
                for modified in info['modified']:
                    f.write(modified + '\n')
                    print(modified)
                
                if len(end_position) != 0 and symbol == end_position[0] :
                    f.write('E {:06X}\n'.format(end_position[1]))
                    print('E {:06X}'.format(end_position[1]))
                else:
                    f.write('E\n')
                    print('E')
                f.write('\n')
                print('\n')

    def execute(self, read_file, write_file , intermediate_file) : # 執行 assembler
        self.scanner(read_file)
        self.pass_one(intermediate_file)
        self.pass_two()
        if (self.__error_flag):
            exit(1)
        else:
            self.write_object_program(write_file)

if __name__ == "__main__":
    print("Two Pass SIC XE Assembler.")
    print("   Usage: 'python 108213053王念祖_SIC_XE.py <input_file>")

    # initial class
    asm = Assembler()
    read_file = sys.argv[1]
    write_file = '108213053王念祖_output.txt'
    intermediate_file = '108213053王念祖_intermediate.txt'

    asm.execute(read_file, write_file , intermediate_file)