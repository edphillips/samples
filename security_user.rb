require 'digest'
#  This model contains logic/business rules for Security Users

class SecurityUser < ActiveRecord::Base  
  load RAILS_ROOT + "/lib/nc2_inc/models/security_user.rb"
  
  attr_accessor :access_id, :district, :user_role_sys_no, :orig_status_code

  accepts_nested_attributes_for :inspector
  
  # Validations
  validates_format_of          :su_first_name, :with => /^[a-zA-Z]+(([\'\,\.\-][a-zA-Z])?[a-zA-Z0-9]*)*$/, :allow_blank=>true, :message => "must start with a letter, and may only contain letters or numbers"
  validates_presence_of      :su_first_name, :message => "is required"
  validates_format_of          :su_last_name, :with => /^[a-zA-Z]+(([\'\,\.\-][a-zA-Z])?[a-zA-Z0-9]*)*$/, :allow_blank=>true, :message => "must start with a letter, and may only contain letters or numbers"
  validates_presence_of      :su_last_name, :message => "is required"
  validates_format_of         :su_email, :with => /\A([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\Z/i, :allow_blank=>true
  validates_presence_of      :su_status_change_reason, :if => "self.su_status_code != self.orig_status_code"
  validates_uniqueness_of   :su_user_id
  validates_length_of          :su_user_id, :maximum=>30
  validates_format_of          :su_user_id, :with => /^[a-zA-Z]+(([\'\,\.\-_][a-zA-Z0-9])?[a-zA-Z0-9]*)*$/, :allow_blank=>false
  validates_confirmation_of :password, :message => " and confirm password do not match", :if =>:validate_password?
  validates_format_of         :password,
    :with => /^.*(?=.{6,40})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#%^&*_~-]).*$/,
    :if => :validate_password?,
    :message => " - please enter a valid password - 6-40 characters. Must contain a minimum of 1 Uppercase, 1 Lowercase, 1 Number, and 1 of these Special Chars - '@#%^&*_~-' "
  
  after_save :save_inspector, :save_pwd_history

  def after_find
    set_attributes
  end
  
  def set_attributes
    set_access_id
    set_district
    set_user_role_sys_no
    set_orig_status_code
    set_status_change_reason
  end

  def save_pwd_history
    return unless su_password_changed?
    pwd_hist = self.security_pwd_histories.build
    pwd_hist.sph_su_password = self.su_password
    pwd_hist.sph_su_salt = self.su_salt
    pwd_hist.save
  end

  def save_inspector
    if !self.inspector.nil?
      self.inspector.insp_id = @access_id
      self.inspector.insp_r_ds_id = @district
      self.inspector.save
    end
  end
  
  def at_least_one_audit_assignment
    if auditor? and validate_at_least_one_audit_assignment?
      
      one_active_audit_assignment = false;
      audit_assignments().each() do |aa|
        one_active_audit_assignment = true if aa.active?
      end
      
      if !one_active_audit_assignment and active?
        errors.add_to_base("Please select at least one audit assignment.")
      end
    end
  end
  
  def create_inspector_row
    if self.inspector.nil?
      self.inspector = Inspector.new do |i|
        i.insp_id = self.access_id
        i.insp_badge_no = i.insp_id
        i.insp_last_nm = self.su_last_name
        i.insp_first_nm = self.su_first_name
        i.insp_mid_nm = self.su_middle_initial
        i.insp_type = 'I'
        i.insp_acc_cd = random_access_code()
        i.insp_ets_access_fl = 'N'
        i.insp_r_ds_id = '99'
        i.insp_auditor_fl = 'N'
      end
    end
  end

  def create_inspector
    create_inspector_row()
    self.inspector.insp_status_fl = 'Y'
    self.inspector.save
    
    create_audit_assignments()
  end

  def revoke_inspector
    if self.inspector
      self.inspector.insp_status_fl = 'N'
      
      if !auditor?
        self.inspector.insp_ets_access_fl = 'N'
      end
      self.inspector.save
    end
    
    revoke_audit_assignments()
  end
  
  def create_auditor
    create_inspector_row()
    if self.su_status_code == 'A'
      self.inspector.insp_ets_access_fl = 'Y'
    else
      self.inspector.insp_ets_access_fl = 'N'
    end
    
    self.inspector.insp_acc_cd ||= random_access_code()
    self.inspector.insp_auditor_fl = 'Y'
    self.inspector.save
    create_audit_assignments()
  end

  def revoke_auditor
    if self.inspector
      self.inspector.insp_auditor_fl = 'N'
      
      if !inspector?
        self.inspector.insp_ets_access_fl = 'N'
      end
      self.inspector.save
    end
    
    revoke_audit_assignments()
  end


  def create_audit_assignments
    if self.inspector.audit_assignments and self.inspector.audit_assignments.length == 0
      
      SAuditType.find(:all).each() do|audit_type|
        
        audit_assignment = AuditAssignment.new do |aa|
          aa.aa_sat_id = audit_type.sat_id
          aa.aa_status = 'A'
          aa.aa_insp_sys_no = self.inspector.insp_sys_no
          self.inspector.audit_assignments << aa
        end
        audit_assignment.save
      end
    end
  end

  def revoke_audit_assignments
    if self.inspector and self.inspector.audit_assignments
      self.inspector.audit_assignments.each() do |audit_assignment|
        audit_assignment.aa_status = 'I'
        audit_assignment.save
      end
    end
  end
  
  def revoke_roles
    if !security_roles.nil?
      security_roles.clear  
    end
  end

  def grant_ets_access
    create_inspector_row()
    self.inspector.insp_ets_access_fl = 'Y'
    self.inspector.save
  end
  
  def revoke_ets_access
    if self.inspector
      self.inspector.insp_ets_access_fl = 'N'
      self.inspector.save
    end
  end
 
  def nextval seq
    cursor = ActiveRecord::Base.connection.execute("(select #{ seq }.nextval val from dual)")
    
    val = 1
    while( r = cursor.fetch())
      val = r[0].to_i
    end
    
    cursor.close
    
    return val
  end
  
  def find_matching_inspector insp_id
    return Inspector.find(:first, 
      {:conditions => ["insp_id = :insp_id AND insp_badge_no = :insp_id", 
        {:insp_id => insp_id}]});
  end
  
  def random_access_code
    10000 + rand(89999)
  end
  
  # virtual attribute  
  def validate_password= (do_password_validation)
    @validate_password = do_password_validation
  end
  
  def validate_password?
    return true if @validate_password.nil?
    return @validate_password
  end

  def validate_at_least_one_audit_assignment= (flag)
    @at_least_one_audit_assignment = flag
  end
  
  def validate_at_least_one_audit_assignment?
    return true if @at_least_one_audit_assignment.nil?
    return @at_least_one_audit_assignment
  end

  def current_password
    @current_password    
  end
  
  def current_password=(pass)
  end
    
  def insp_sys_no
    @insp_sys_no
  end
  
  def insp_sys_no=(insp_sys_no)
    @insp_sys_no = insp_sys_no
    if !insp_sys_no.blank?
      self.inspector = Inspector.find_by_insp_sys_no(insp_sys_no)
      self.inspector.security_user = self
    end
  end
  
  def suggested_user_ids
    ids = Array.new
    
    if( !su_first_name.blank? and  !su_last_name.blank?)
      
      if( su_first_name.length > 12)
        fname = su_first_name[0,12]
      else
        fname = su_first_name
      end
      
      if( su_last_name.length > 12)
        lname = su_last_name[0,12]
      else
        lname = su_last_name
      end
      
      push_id ids, "#{fname}.#{lname}"
    end
    
    index = 1
    while(ids.size < 2 and !su_first_name.blank? and  !su_last_name.blank?) 
      push_id ids, "#{fname.to_s}.#{lname.to_s}_#{index}"
      index += 1
    end
    
    return ids
  end
  
  def push_id(ids, id)
    
    id.upcase!
    
    if( id.length > 50)
      id = id[0,50]
    end
    
    if( !SecurityUser.find_by_su_user_id(id) )
      ids << id
    end
    
    ids.uniq!
  end
  
  def set_access_id
    @access_id = inspector.nil? ? '' : inspector.insp_id.to_s
  end
  
  def access_code
    if inspector
      return inspector.insp_acc_cd.to_s.rjust(5,'0')
    end
    return ''
  end
  
  def set_district
    @district = inspector.nil? ? 99 : inspector.insp_r_ds_id
  end
  
  def audit_assignments
      return (SAuditType.find(:all,:conditions => "sat_status = 'A'" ).collect() {|at|
        aa = AuditAssignment.new
        
        aa.aa_sat_id = at.sat_id
        aa.aa_status = at.sat_status
        
        aa;
      })
  end
  
  def audit_assignments= (assignments)
    if inspector
      inspector.audit_assignments.each do |assignment|
        assignment.aa_status = 'A' 
        assignment.save
      end
    end
  end

  def set_user_role_sys_no
    user_roles = self.security_roles.collect { |sr| sr.sr_name }
    
    if user_roles.include? 'Administrator'
        @user_role_sys_no = self.security_roles.find_by_sr_name('Administrator').sr_sys_no
    elsif user_roles.include? 'Supervisor'
        @user_role_sys_no = self.security_roles.find_by_sr_name('Supervisor').sr_sys_no
    elsif user_roles.include? 'Inspector'
        @user_role_sys_no = self.security_roles.find_by_sr_name('Inspector').sr_sys_no
    else
        @user_role_sys_no = self.security_roles.find_by_sr_name(user_roles[0]).sr_sys_no
    end
  end

  def set_orig_status_code
    @orig_status_code = su_status_code
  end
  
  def set_status_change_reason
    self.su_status_change_reason = ''
  end

end
