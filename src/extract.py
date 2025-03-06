"""
Extract OONI data from a folder and put
the results into a cumulative database
"""

# Local Imports
import argparse
import csv
import gzip
import json
import os
import pickle
from tqdm import tqdm


def jsonl_gz_to_list(filename):
    """
    Take a given .jsonl.gz and extract the data
    into a list of objects.

    Parameters
    ----------
    filename : str
        The filename to open (.jsonl.gz)

    Returns
    -------
    objs : list
        A list of objects
    """

    # List of outputs
    objs = []
    
    # Open the given file
    with gzip.open(filename, 'r') as fp:
        lines = fp.read().decode('utf-8').split('\n')
        for line in lines:
            if (line != ''):
                try:
                    objs.append(json.loads(line))
                except:
                    # Just ignore failures
                    pass

    return objs

def process_schema(obj, schema):
    """
    Process a given object with a specific
    schema.

    Parameters
    ----------
    obj : dict
        An
    schema : str
        The specific schema type to use to
        extract data

    Returns
    -------
    out : dict

    """

    out = {}

    # Get relevant information present in all entries
    out["probe_asn"] = obj["probe_asn"]
    test_keys = obj["test_keys"]
    
    # Parse specific information for each schema
    if (schema == "dash"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "dnscheck"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["bootstrap_failure"]
    elif (schema == "facebookmessenger"):
        out["facebook_b_api_dns_consistent"] = test_keys["facebook_b_api_dns_consistent"]
        out["facebook_b_api_reachable"] = test_keys["facebook_b_api_reachable"]
        out["facebook_b_graph_dns_consistent"] = test_keys["facebook_b_graph_dns_consistent"]
        out["facebook_b_graph_reachable"] = test_keys["facebook_b_graph_reachable"]
        out["facebook_dns_blocking"] = test_keys["facebook_dns_blocking"]
        out["facebook_edge_dns_consistent"] = test_keys["facebook_edge_dns_consistent"]
        out["facebook_edge_reachable"] = test_keys["facebook_edge_reachable"]
        out["facebook_external_cdn_dns_consistent"] = test_keys["facebook_external_cdn_dns_consistent"]
        out["facebook_external_cdn_reachable"] = test_keys["facebook_external_cdn_reachable"]
        out["facebook_scontent_cdn_dns_consistent"] = test_keys["facebook_scontent_cdn_dns_consistent"]
        out["facebook_scontent_cdn_reachable"] = test_keys["facebook_scontent_cdn_reachable"]
        out["facebook_star_dns_consistent"] = test_keys["facebook_star_dns_consistent"]
        out["facebook_star_reachable"] = test_keys["facebook_star_reachable"]
        out["facebook_stun_dns_consistent"] = test_keys["facebook_stun_dns_consistent"]
        out["facebook_stun_reachable"] = test_keys["facebook_stun_reachable"]
        out["facebook_tcp_blocking"] = test_keys["facebook_tcp_blocking"]
    elif (schema == "httpheaderfieldnamnipulation"):
        tampering = test_keys["tampering"]
        out["header_field_name"] = tampering["header_field_name"]
        out["header_field_number"] = tampering["header_field_number"]
        out["header_field_value"] = tampering["header_field_value"]
        out["header_name_capitalization"] = tampering["header_name_capitalization"]
        out["request_line_capitalization"] = tampering["request_line_capitalization"]
        out["total"] = tampering["total"]
    elif (schema == "httpinvalidrequestline"):
        tampering = test_keys["tampering"]
        out["tampering"] = tampering
    elif (schema == "ndt"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "psiphon"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "riseupvpn"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "signal"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
        out["signal_backend_status"] = test_keys["signal_backend_status"]
        out["signal_backend_failure"] = test_keys["signal_backend_failure"]
    elif (schema == "stunreachability"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "telegram"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys.get("failure")
        out["telegram_http_blocking"] = test_keys.get("telegram_http_blocking")
        out["telegram_tcp_blocking"] = test_keys.get("telegram_tcp_blocking")
        out["telegram_web_failure"] = test_keys.get("telegram_web_failure")
        out["telegram_web_status"] = test_keys.get("telegram_web_status")
    elif (schema == "tor"):
        # Handle empty test keys:
        if (test_keys is None):
            test_keys = {
                "dir_port_total": 0,
                "dir_port_accessible": 0,
                "obfs4_total": 0,
                "obfs4_accessible": 0,
                "or_port_dirauth_total": 0,
                "or_port_dirauth_accessible": 0,
                "or_port_total": 0,
                "or_port_accessible": 0
            }

        # Handle data regularly
        out["resolver_asn"] = obj["resolver_asn"]
        out["dir_port_total"] = test_keys["dir_port_total"]
        out["dir_port_accessible"] = test_keys["dir_port_accessible"]
        out["obfs4_total"] = test_keys["obfs4_total"]
        out["obfs4_accessible"] = test_keys["obfs4_accessible"]
        out["or_port_dirauth_total"] = test_keys["or_port_dirauth_total"]
        out["or_port_dirauth_accessible"] = test_keys["or_port_dirauth_accessible"]
        out["or_port_total"] = test_keys["or_port_total"]
        out["or_port_accessible"] = test_keys["or_port_accessible"]
    elif (schema == "torsf"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "vanillator"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys["failure"]
    elif (schema == "webconnectivity"):
        out["input"] = obj["input"]
        out["resolver_asn"] = obj["resolver_asn"]
        out["control_failure"] = test_keys.get("control_failure")
        out["x_dns_flags"] = test_keys.get("x_dns_flags")
        out["dns_experiment_failure"] = test_keys.get("dns_experiment_failure")
        out["dns_consistency"] = test_keys.get("dns_consistency")
        out["http_experiment_failure"] = test_keys.get("http_experiment_failure")
        out["x_blocking_flags"] = test_keys.get("x_blocking_flags")
        out["x_null_null_flags"] = test_keys.get("x_null_null_flags")
        out["body_proportion"] = test_keys.get("body_proportion")
        out["body_length_match"] = test_keys.get("body_length_match")
        out["headers_match"] = test_keys.get("headers_match")
        out["status_code_match"] = test_keys.get("status_code_match")
        out["title_match"] = test_keys.get("title_match")
        out["blocking"] = test_keys.get("blocking")
        out["accessible"] = test_keys.get("accessible")
    elif (schema == "whatsapp"):
        out["resolver_asn"] = obj["resolver_asn"]
        out["failure"] = test_keys.get("failure")
        out["registration_server_failure"] = test_keys.get("registration_server_failure")
        out["registration_server_status"] = test_keys.get("registration_server_status")
        out["whatsapp_endpoints_blocked"] = len(test_keys.get("whatsapp_endpoints_blocked"))
        out["whatsapp_endpoints_dns_inconsistent"] = len(test_keys.get("whatsapp_endpoints_dns_inconsistent"))
        out["whatsapp_endpoints_status"] = test_keys.get("whatsapp_endpoints_status")
        out["whatsapp_web_failure"] = test_keys.get("whatsapp_web_failure")
        out["whatsapp_web_status"] = test_keys.get("whatsapp_web_status")

    return out

def aggregate(base_dir, schema):
    """
    Loop through all data from all directories
    in a given starting folder and aggregate
    their results into a single object.

    Parameters
    ----------
    base_dir : str
        The top level folder to search
    schema : str
        The specific schema type to use to
        extract data
    
    Returns
    -------
    out : list
        A list of all entries organized
        by date, network, test name, and ASN
    """

    # Create output list
    out = []

    # Loop through all sources
    for d in tqdm(os.listdir(base_dir)):
        # Only open directories
        sd = os.path.join(base_dir, d)
        if (os.path.isdir(sd)):
            # Get all files in this directory
            for f in os.listdir(sd):
                fname = os.path.join(sd, f)
                if (not os.path.isdir(fname) and os.path.splitext(fname)[-1] == ".gz"):
                    # Extract jsonl.gz to a list
                    o = jsonl_gz_to_list(fname)

                    # Loop through all entries
                    for e in o:
                        if (e is not None):
                            # Get specific info from a schema
                            o = process_schema(e, schema)

                            # Add date to the entry
                            o["date"] = d

                            # Add the entry to the final output
                            out.append(o)

    return out

def aggregate_all(base_dir):
    """
    This aggregates over all directories
    using their names as the schema type.

    Parameters
    ----------
    base_dir : str
        The top level directory to loop over
    
    Returns
    -------
    out : dict
        A dictionary of lists which contain
        entries over date ranges for each
        schema type
    """

    # Create output dictionary
    out = {}

    # Loop through all top level directories
    for d in os.listdir(base_dir):
        # Only open directories
        sd = os.path.join(base_dir, d)
        if (os.path.isdir(sd)):
            print(d)
            o = aggregate(sd, d)
            out[d] = o

    return out

def aggregate_to_csv(data, out_filename):
    """
    Take a list of dictionaries and output
    them to a csv file.

    Parameters
    ----------
    data : list
        A list of dictionaries containing
        data entries
    out_filename : str
        The name of the output file to write
    """
    
    # Get header info
    header = set()
    for d in data:
        header.update(d.keys())

    # Re-order header info
    hh = ["date", "probe_asn"]
    for h in header:
        if h not in hh:
            hh.append(h)

    # Sort data by date
    sorted_data = sorted(data, key=lambda d: d["date"])

    # Write csv file
    with open(out_filename, "w") as fp:
        wr = csv.DictWriter(fp, delimiter=",", fieldnames=hh)
        wr.writeheader()
        for d in sorted_data:
            wr.writerow(d)


def main(input_dir, output_dir):
    """
    """

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Extract directory name
    bname = os.path.basename(input_dir)

    # Aggregate all results
    f = aggregate_all(input_dir)

    # Store results in the output directory
    print(os.path.join(output_dir, bname + "_aggregate.pkl"))
    with open(os.path.join(output_dir, bname + "_aggregate.pkl"), 'wb') as fp:
        pickle.dump(f, fp)
    
    # Convert results into CSV files
    for k, v in f.items():
        aggregate_to_csv(v, os.path.join(output_dir, k + ".csv"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="extract",
        description="OONI data extractor"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="The input directory to parse"
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The output directory to store results"
    )
    args = parser.parse_args()
    main(args.input, args.output)