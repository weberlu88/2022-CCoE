# 2022-CCoE
論文 & 資安卓越計畫 | Cybersecurity Center of Excellence Program  
Note that this is a private repo.

## Requirements
1. Python3 version10
2. Python packages. not yet inventoried them.
3. Install `graphviz` on our computer and add bin folder to path. See [stackoverflow](https://stackoverflow.com/questions/72754723/graphviz-installation-and-the-instruction-for-use).
4. Before cloning the repo from github, add the local repo path to [windows defender's whitelist](https://support.microsoft.com/en-us/windows/add-an-exclusion-to-windows-security-811816c0-4dfd-af4a-47e4-c301afe13b26).

## Directory Structure
- Run the malware CTI report evaluation code at: `\Model\Exp5_step`. The `e_darlloz.ipynb` will eval all the reports subject to darlloz malware family.
- View existing results at: `\Model\Exp5_step\result` and `\Model\Exp5_step\imgs`.
  - `\Model\Exp5_step\result\_info.csv` store all value and intermediate value of metrics. The .ipynb code will edit this file.
  - `_quality_metrics.csv` store only the 4 quality metrics.
- View or add malware CTI reports at: `\C parse report`. Each report will save as 3 formats:
  - html/pdf: Archive of the report. Download by [Singlefile](https://chrome.google.com/webstore/detail/singlefile/mpiodijhokgodhhofbcjdecpffjipkle).
  - txt: Manual extract the text content from html. I provide a PDF crawling script.
  - csv: After sentence segmentation. The evaluation code will read the csvs as input.
- View or add malware profiling system call traces at: `\C ASG\trace` or `C ASG statistics 1115ver`.
  - The sandbox is seperate from this system. The malware exec binary didn't store this repo.
- Find malware sample information at: `CCoE\C malware info`.
  - Store the malware's family, filename, hashes, executable or not, and the ASG object counts, ASG step counts.
  - Pick one sample represent the whole malware family.
- The draft area for Spacy Dependency Parser: `\C sent nlp\比較Dofloo各樣本的ST`.
  - Out put dp images at: `\C sent nlp\images`
