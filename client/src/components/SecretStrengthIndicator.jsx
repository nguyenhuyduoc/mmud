export default function SecretStrengthIndicator({ value }) {
  const calculateStrength = (text) => {
    if (!text) return 0;
    
    let score = 0;
    
    // Length score
    if (text.length >= 8) score += 15;
    if (text.length >= 12) score += 15;
    if (text.length >= 16) score += 10;
    
    // Character variety
    if (/[a-z]/.test(text)) score += 15;
    if (/[A-Z]/.test(text)) score += 15;
    if (/[0-9]/.test(text)) score += 15;
    if (/[^a-zA-Z0-9]/.test(text)) score += 15;
    
    return Math.min(score, 100);
  };
  
  const strength = calculateStrength(value);
  
  const getColor = () => {
    if (strength < 40) return '#dc3545'; // Red
    if (strength < 70) return '#ffc107'; // Yellow
    return '#28a745'; // Green
  };
  
  const getLabel = () => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };
  
  if (!value) return null;
  
  return (
    <div style={styles.container}>
      <div style={styles.barBackground}>
        <div 
          style={{
            ...styles.barFill,
            width: `${strength}%`,
            backgroundColor: getColor()
          }}
        />
      </div>
      <div style={styles.info}>
        <span style={{ ...styles.label, color: getColor() }}>
          {getLabel()}
        </span>
        <span style={styles.score}>{strength}%</span>
      </div>
    </div>
  );
}

const styles = {
  container: {
    marginTop: '8px',
    marginBottom: '8px'
  },
  barBackground: {
    width: '100%',
    height: '6px',
    backgroundColor: '#e9ecef',
    borderRadius: '3px',
    overflow: 'hidden'
  },
  barFill: {
    height: '100%',
    transition: 'width 0.3s ease, background-color 0.3s ease',
    borderRadius: '3px'
  },
  info: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: '4px'
  },
  label: {
    fontSize: '13px',
    fontWeight: '600'
  },
  score: {
    fontSize: '12px',
    color: '#6c757d'
  }
};
