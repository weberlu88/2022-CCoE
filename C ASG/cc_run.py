from cc_module import build
import pandas as pd
import pickle

def get_executable_sample() -> dict:
    df = pd.read_csv("../C malware info/sample_info.csv")
    family_lst = df.family.unique()
    sample_dct = {}
    for key in family_lst:
        sample_dct[key] = []

    for idx, row in df.iterrows():
        if row.platform in ['X86_64','X86','ARM']:
            sample_dct[row.family].append(row.filename)
    return sample_dct

# 取得trace log資料夾名稱，記得先確認 family 資料夾名稱
sample_dct = get_executable_sample()

with open('sample_dct.pkl', 'wb') as outp:
    pickle.dump(sample_dct, outp, pickle.HIGHEST_PROTOCOL)

test_samples = {
    'Dofloo-all': ['9a37fcc7eab08d59532bc5c66390bc30.bin','26d45f2e2d360ff1707c734006878dcb.bin','44d98df44327179d1a11dce725d0fa4a.bin'],
    'Mirai-all': ['0a38acadeb41536f65ed89f84cc1620fb79c9b916e0d83f2db543e12fbfd0d8c.bin', '3d604ebe8e0f3e65734cd41bb1469cea3727062cffc8705c634558afa1997a7a.bin', '3d9487191dd4e712cbfb8f4dcf916a707f60c3fb23807d4c02fb941e216f951d.bin','ac13002f74249e0eab2dacb596a60323130664b8c19d938af726508fdc7500a2.bin'],
    'Mozi-all': ['b9f23009ff836e3a368cd7adf701b6e7.bin', '567b30e6033bd831ef2190c5ad863ff3.bin', 'bc3382acc65d23955eb48132961a8221.bin'],
    'Tsunami-all': ['7d3855bb09f2f6111d6c71e06e1e6b06dd47b1dade49af0235b220966c2f5be3.bin', '16b4093813e2923e9ee70b888f0d50f972ac607253b00f25e4be44993d263bd2.bin' ,'28443c0a9bfd8a12c12a2aad3cc97d2e8998a9d8825fcf3643d46012f18713f0.bin'],
    'Xorddos-all': ['0aefb67c01a24d05351b093455203fa2.bin', '0bc90c333f08237475a08c7158aba345.bin', '07c070b717a23453a2b71c7582d6a928.bin', '7eba17d4ea5615e239c00e47d182e08a.bin']
}

for family_name in sample_dct:
    # for s in test_samples[family_name]:
    #     build(family_name, s)
    [build(family_name, s) for s in sample_dct[family_name]]