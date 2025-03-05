# Data Science Project

## Installation

```bash
$ conda create -n "ooni" python=3.9.21 ipython
$ conda init
$ source ~/.bashrc
(base) $ conda activate ooni
(ooni) $ pip install oonidata
(ooni) $ conda install numpy scikit-learn pandas tqdm
(ooni) $ conda install -c conda-forge jupyterlab nb_conda_kernels
```

## Getting OONI Data

```bash
(ooni) $ python ~/.conda/envs/ooni/lib/python3.9/site-packages/oonidata/cli/command.py sync --probe-cc <cc> --start-day <start> --end-day <end> --output-dir <dir>
```

## Extraction

```bash
(ooni) $ python ./src/extract.py -i <folder> -o <processed_folder>
```

## Analysis
