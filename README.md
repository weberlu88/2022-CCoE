# 2022-CCoE
論文 & 資安卓越計畫 | Cybersecurity Center of Excellence Program  
Note that this is a private repo.

## Requirements
1. Python3 version10
2. Python packages. not yet inventoried them.
3. Install `graphviz` on our computer and add bin folder to path. See [stackoverflow](https://stackoverflow.com/questions/72754723/graphviz-installation-and-the-instruction-for-use).
4. Before cloning the repo from github, add the local repo path to [windows defender's whitelist](https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26).

## 惡意程式資料集
Malware sample 和 trace log 存在哪裡?

## Directory Structure
- Run the malware CTI report evaluation code at: `\Model\Exp5_step`. The `e_darlloz.ipynb` will eval all the reports subject to darlloz malware family.
- View existing results at: `\Model\Exp5_step\result` and `\Model\Exp5_step\imgs`.
  - 每個樣本的 code 是一隻 ipynb，e_ 開頭的檔名是 CCoE 給的樣本， i_ 開頭的檔名是資策會給的樣本。兩者只差在樣本 trace 載入的方法不一樣(不同時期寫的code)。需求一直反覆改來改去，所以 code 很長很髒QQ，建議重作成打包成獨立檔案的模組。
  - `\Model\Exp5_step\result\_info.csv` store all value and intermediate value of metrics. The .ipynb code will edit this file.
  - `_quality_metrics.csv` store only the 4 quality metrics.
- View or add malware CTI reports at: `\C parse report`. Each report will save as 3 formats:
  - html/pdf: Archive of the report. Download by [Singlefile](https://chrome.google.com/webstore/detail/singlefile/mpiodijhokgodhhofbcjdecpffjipkle).
  - txt: Manual extract the main text content from html. I provide a PDF crawling script.
  - csv: After sentence segmentation. The evaluation code will read the csvs as input.
  - The csv file `/C parse report/report htmls/0_info.csv` store the metadata of CTI report.
    - The $Genre$ attribute. May belongs to *analysis*, *tech*, *news* and *campaign* 4 genres.
    - The $Txtname$ attribute store the filename. For instance, with `Dofloo-BleepingComputer` Txtname, you can find `Dofloo-BleepingComputer.txt` and `Dofloo-BleepingComputer.csv` two origin files. The filename of txt & csv are the same, but differ from html filename.
- View or add malware profiling system call traces at: `\C ASG\trace` or `C ASG statistics 1115ver`.
  - The sandbox is seperate from this system. The malware exec binary didn't store this repo.
- Find malware sample information at: `CCoE\C malware info`.
  - Store the malware's family, filename, hashes, executable or not, and the ASG object counts, ASG step counts.
  - Pick one sample represent the whole malware family.
- The draft area for Spacy Dependency Parser: `\C sent nlp\比較Dofloo各樣本的ST`.
  - Out put dp images at: `\C sent nlp\images`

## 注意事項
> 以下內容，視情況再跟老師說明。沒事的話最好別讓他知道。
1. **synbase** 有兩個版本 (精簡版跟完整版)。上線運作使用的是 `Model/rule_dataset.csv`。
  - 精簡版: 93 個 syscall，`Model/rule_dataset.csv`。因為實際用到的舊這麼多 (應該)。
  - 完整版: 354 個 syscall，`C syscall/rule_dataset.csv`。
2. synbase 完整版收錄了動詞片語(兩個字以上)。但是目前系統的動詞抓取系統，只能吃一個動詞，要吃動詞片語要麻煩你修改喔。
  - 動詞抓取系統程式碼: `Model/Exp5_step/cc_nlp_script.py` 的 find_verb_of_vocab() 和 OperationEvaluator::word_vector_from_BERT()。
3. Keyplug 樣本的 metrics 因為 regex 的 bug 而算錯，目前用人工修改產出 info.csv 的分數。詳細可以看 git commit 的描述。
  - Basic Search Rule.xlsx 是志剛寫的 regex 規則，應該要從這裡下手。
4. 每次系統抓到的 AA description pair 會不太一樣，因為是用 set 儲存沒有排序，但 matched 到的 steps 一樣。舉例: 文章裡面可能會有多個 <add, rc.d/rc*> 的句子，他們對應到的 steps 都一樣，但我無法控制要抓哪個句子。(當初沒想太多)