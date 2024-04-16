import os
import argparse
import sys
import time
import numpy as np
import matplotlib.pyplot as plt
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text
import vulnerability_factors as vul

console = Console()

term_width = os.get_terminal_size().columns

def clear_screen():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def show_banner():
    banner_lines = "=" * term_width
    banner_title = "[bold magenta]Risk Assessment Tool[/bold magenta]"
    banner_subtitle = "[bold]Comprehensive Security and Risk Evaluation[/bold]"
    banner_description = "A tool designed to systematically evaluate risk by assessing vulnerability, technical impact, business impact, and threat agent factors."
    
    console.print(banner_lines)
    console.print(banner_title, justify="center")
    console.print(banner_subtitle, justify="center")
    console.print(banner_description, justify="center")
    console.print(banner_lines)
    console.print("[italic]Begin your assessment to identify and mitigate risks effectively.[/italic]", justify="center")

def loading_animation(duration):
    animation_chars = ['|', '/', '-', '\\']
    start_time = time.time()
    while time.time() - start_time < duration:
        for char in animation_chars:
            sys.stdout.write('\r' + 'Loading ' + char)
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 10 + '\r')
    sys.stdout.flush()

def ask_question(question, options):
    console.print(f"\n[bold cyan]{question}[/bold cyan]")
    for index, option in enumerate(options, start=1):
        color = ["green", "yellow", "orange", "red"][(index - 1) % 4]
        option_text = Text()
        option_text.append(f"{index}", style=f"bold {color}")
        option_text.append(". ")
        option_text.append(option, style=color)
        console.print("\t", option_text, end=" ")
    print("\n")

    while True:
        try:
            choice = int(Prompt.ask("[bold]~[/bold]").strip(": "))
            if 1 <= choice <= len(options):
                return choice
            else:
                console.print("[bold red]Please enter a valid option number.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid input. Please enter a numeric value.[/bold red]")

def ask_questions(header, questions):
    line = "------------------------------------"
    console.print(f"[bold cyan]{line.center(term_width)}[/bold cyan]")
    console.print(f"[bold cyan]{header.center(term_width)}[/bold cyan]")
    console.print(f"[bold cyan]{line.center(term_width)}[/bold cyan]")
    scores = [ask_question(question, options) for question, options in questions]
    return sum(scores)

def vulnerability_factors(args, report_type=None):
    max_score = 15
    vuln_score = None
    report_path_burp = args.burp_report if hasattr(args, 'burp_report') else None
    report_path_nessus = args.nessus_report if hasattr(args, 'nessus_report') else None

    if report_path_burp:
        try:
            vuln_score = float(vul.get_report(report_path_burp, report_type='burp'))
            console.print(f"[bold green]Vulnerability score calculated from Burp report: {vuln_score}%[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error processing Burp report: {e}.[/bold red]")
    
    if vuln_score is None and report_path_nessus:
        try:
            vuln_score = float(vul.get_report(report_path_nessus, report_type='nessus'))
            console.print(f"[bold green]Vulnerability score calculated from Nessus report: {vuln_score}%[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error processing Nessus report: {e}.[/bold red]")

    if vuln_score is None:
        console.print("[bold yellow]No valid report found or both reports failed to process. Proceeding with manual input.[/bold yellow]")
        score = ask_questions("Vulnerability Factors", [
            ("Ease of Discovery:", ["Automated tools available.", "Easy.", "Difficult.", "Impossible."]),
            ("Ease of Exploitation:", ["Automated tools available.", "Easy.", "Difficult.", "Theory only."]),
            ("Awareness of Vulnerability:", ["Publicly known.", "Hidden.", "Unknown."]),
            ("Detection in IDS/IPS:", ["Not logged.", "Logged without review.", "Logged and reviewed.", "Active detection in application."])
        ])
        vuln_score = ((score / max_score) * 100) / 4

    return vuln_score

def technical_impact_factors():
    max_score = 15
    score = ask_questions("Technical Impact Factors", [
        ("Loss of Confidentiality:", [
            "Nothing disclosed.",
            "Non-sensitive data disclosed.",
            "Sensitive data disclosed.",
            "All data disclosed."
        ]),
        ("Loss of Integrity:", [
            "Nothing corrupted.",
            "Minimal data corrupted.",
            "Sensitive data corrupted.",
            "All data corrupted."
        ]),
        ("Loss of Availability:", [
            "Nothing interrupted.",
            "Secondary services interrupted.",
            "Primary services interrupted.",
            "All services interrupted."
        ]),
        ("Loss of Accountability:", [
            "The attack is fully traceable to an individual.",
            "The attack is possibly traceable.",
            "Attack is anonymous."
        ])
    ])
    return ((score / max_score) * 100) / 4

def business_impact_factors():
    max_score = 12
    score = ask_questions("Business Impact Factors", [
        ("Financial Damage Assessment:", [
            "Minor effect on annual profits.",
            "Major effect on annual profits.",
            "Bankruptcy."
        ]),
        ("Reputational Damage Assessment:", [
            "Minimal damage.",
            "Loss of a major account.",
            "Brand damage."
        ]),
        ("Non-Compliance Status:", [
            "Minor violation.",
            "Major violation."
        ]),
        ("Privacy Violation Level:", [
            "One individual.",
            "Hundreds of people.",
            "Thousands of people.",
            "Millions of people."
        ])
    ])
    return ((score / max_score) * 100) / 4

def threat_agent_factors():
    max_score = 14
    score = ask_questions("Threat Agent Factors", [
        ("Skills Required for Attacker:", [
            "Advanced penetration testing skills.",
            "Script kiddie.",
            "Minimal computer and network knowledge.",
            "No knowledge."
        ]),
        ("Motive of an Attacker:", [
            "No reward or personal gain.",
            "Possible reward.",
            "High reward."
        ]),
        ("Level of Access:", [
            "Fully expensive resources required.",
            "Special access to tools is required.",
            "No resources required."
        ]),
        ("Population:", [
            "System administrators.",
            "Intranet users.",
            "Authenticated users.",
            "Anonymous users."
        ])
    ])
    return ((score / max_score) * 100) / 4

def calculate_risk_score(args):
    report_risk_score = 0
    manual_input_needed = True

    if hasattr(args, 'burp_report') and args.burp_report:
        try:
            burp_risk_score = vulnerability_factors(args, 'burp')
            console.print(f"\n[bold magenta]Risk Score from Burp Report: {burp_risk_score:.2f}%[/bold magenta]")
            report_risk_score += burp_risk_score
            manual_input_needed = False
        except Exception as e:
            console.print(f"[bold red]Failed to process Burp report: {e}[/bold red]")

    if hasattr(args, 'nessus_report') and args.nessus_report:
        try:
            nessus_risk_score = vulnerability_factors(args, 'nessus')
            console.print(f"\n[bold magenta]Risk Score from Nessus Report: {nessus_risk_score:.2f}%[/bold magenta]")
            report_risk_score += nessus_risk_score
            manual_input_needed = False
        except Exception as e:
            console.print(f"[bold red]Failed to process Nessus report: {e}[/bold red]")

    if manual_input_needed:
        vulnerability = vulnerability_factors(args)
    else:
        vulnerability = report_risk_score / 2

    clear_screen()

    technical_impact = technical_impact_factors() 
    clear_screen()
    business_impact = business_impact_factors() 
    clear_screen()
    threat_agent = threat_agent_factors() 
    clear_screen()
    show_banner()

    risk_score = vulnerability + technical_impact + business_impact + threat_agent
    loading_animation(5)
    console.print(f"\n[bold green]Vulnerability Risk Score: {vulnerability:.2f}%[/bold green]")
    console.print(f"\n[bold magenta]Total Risk Calculated (including Vulnerability Score): {risk_score:.2f}%[/bold magenta]")

    perform_mc = Prompt.ask("\n[bold cyan]Do you want to perform Monte Carlo simulation? (yes/no)[/bold cyan]", default="no")
    if perform_mc.lower() == "yes":
        perform_monte_carlo_simulation()

    console.print("\n[bold magenta]Thank you for using our tool, hope to see you soon![/bold magenta]")
    sys.exit()

def monte_carlo_simulation_questions():
    console.print("\n[bold cyan]Monte Carlo Simulation Parameters[/bold cyan]")
    min_loss = request_input("[bold cyan]Enter the minimum loss from an attack ($):[/bold cyan]")
    max_loss = request_input("[bold cyan]Enter the maximum loss from an attack ($):[/bold cyan]")
    num_trials = request_input("[bold cyan]Enter the number of trials for the simulation:[/bold cyan]")
    event_probability = request_input("[bold cyan]Enter the estimated loss event probability (e.g., 60 for 60%):[/bold cyan]")
    control_probability = request_input("[bold cyan]Enter the probability of an estimated loss after controls (e.g., 10 for 10%):[/bold cyan]")

    return float(min_loss), float(max_loss), int(num_trials), float(event_probability) / 100, float(control_probability) / 100

def perform_monte_carlo_simulation():
    console.print("\n[bold green]Performing Monte Carlo simulation...[/bold green]")
    min_loss, max_loss, num_trials, event_probability, control_probability = monte_carlo_simulation_questions()

    mean, std_dev = calculate_lognorm_params(min_loss, max_loss)

    estimated_losses = simulate_losses(mean, std_dev, event_probability, num_trials)
    controlled_losses = simulate_losses(mean, std_dev, control_probability, num_trials)

    plot_series(min_loss, max_loss, estimated_losses, controlled_losses, num_trials)

def request_input(prompt):
    return Prompt.ask(prompt)

def request_loss_range():
    min_loss = request_input("[bold cyan]Enter the minimum loss from an attack ($):[/bold cyan]")
    max_loss = request_input("[bold cyan]Enter the maximum loss from an attack ($):[/bold cyan]")
    return float(min_loss), float(max_loss)

def calculate_lognorm_params(min_loss, max_loss):
    min_log = np.log(min_loss)
    max_log = np.log(max_loss)
    mean = (min_log + max_log) / 2
    std_dev = (max_log - min_log) / np.sqrt(12)
    return mean, std_dev

def simulate_losses(mean, std_dev, probability, num_trials):
    losses = np.random.lognormal(mean, std_dev, size=num_trials)
    random_factors = np.random.rand(num_trials) < probability
    return losses * random_factors

def plot_series(min_loss, max_loss, estimated_losses, controlled_losses, num_trials):
    x_values = np.linspace(min_loss, max_loss, num_trials)
    l_series = np.mean(estimated_losses[:, None] >= x_values, axis=0)
    m_series = np.mean(controlled_losses[:, None] >= x_values, axis=0)
    k_series = np.maximum(0.8 * m_series, 0.01)

    plt.figure(figsize=(12, 6))
    plt.plot(x_values, l_series * 100, label='Before Control', color='blue', linewidth=2)
    plt.plot(x_values, m_series * 100, label='After Control', color='orange', linewidth=2)
    plt.plot(x_values, k_series * 100, label='Acceptable Loss Threshold', color='red', linestyle='--', linewidth=2)
    
    plt.title('Loss Probability Analysis')
    plt.xlabel('Loss Value ($)')
    plt.ylabel('Probability of Loss ≥ x (%)')
    plt.yticks(np.arange(0, 101, 10))
    plt.legend()
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.show()

def main():
    show_banner()

    parser = argparse.ArgumentParser(description="Process report files and calculate vulnerability scores.")
    parser.add_argument("--burp-report", help="Path to the Burp XML report file")
    parser.add_argument("--nessus-report", help="Path to the Nessus HTML report file")
    args = parser.parse_args()

    calculate_risk_score(args)

if __name__ == "__main__":
    main()
