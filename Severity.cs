public enum Severity : byte
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
        [System.ComponentModel.Description("The severity is not set.")]
        NotSet = 5
    }