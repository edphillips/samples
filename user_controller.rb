class UserController < ApplicationController

  filter_parameter_logging :password, 
    :current_password,
    :password_confirmation,
    :su_password
  
  add_breadcrumb "Home", "/"

  def index
    add_breadcrumb 'Search', '/user'
    @roles = ":ALL;"+SecurityRole.find(:all,:order => "sr_name ASC").collect{|i|i.sr_name.upcase + ':' + i.sr_name.upcase}.join(';')    
    @districts = ":ALL;"+ RDistrict.find(:all,:order => "r_ds_nm ASC").collect{|i|i.r_ds_nm + ':' + i.r_ds_nm}.join(';')    
  end
  
  def search
    
    users = VwSecurityUser.find(:all) do
      
      user_id_upper     =~ "%#{params[:user_id].upcase}%"     if params[:user_id].present?
      last_name_upper   =~ "%#{params[:last_name_upper].upcase}%"   if params[:last_name_upper].present?
      first_name_upper  =~ "%#{params[:first_name_upper].upcase}%"  if params[:first_name_upper].present?
      middle_name_upper  =~ "%#{params[:middle_name_upper].upcase}%"  if params[:middle_name_upper].present?
      district  == "#{params[:district]}"  if params[:district].present?
      status  == "#{params[:status]}"  if params[:status].present?
      
      if( params[:roles].present?)
        role == "#{params[:roles]}"
      else
        role == nil
      end

      paginate :page => params[:page], :per_page => params[:rows]
      order_by "#{params[:sidx]} #{params[:sord]}"
    end
    
    if request.xhr?
      render :json => users.to_jqgrid_json(
        [:id,:user_id,:last_name_upper,:first_name_upper,:middle_name_upper,:district,:roles,:status], 
          params[:page], 
          params[:rows], 
          users.total_entries) and return
    end
    
  end
  
  def status_history
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no], :order => "su_create_dt"
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{params[:su_sys_no]}"
    add_breadcrumb "Status History"
    
    if request.xhr?
      render :json => @user.security_users_histories.collect{|i|i.text} and return
    end
    
  end
  
  def new
    @user = SecurityUser.new
    
    inspector = Inspector.find(:first, 
      :conditions => [ "insp_sys_no = ?",params[:insp_sys_no] ])
    
    @user.su_first_name = inspector.insp_first_nm.strip
    @user.su_middle_initial = inspector.insp_mid_nm.strip
    @user.su_last_name = inspector.insp_last_nm.strip
    @user.insp_sys_no = params[:insp_sys_no]

    flash.now[:notice] = "It appears that #{@user.name()} does not have a user account. Please take a moment to set one up now."
 
    add_breadcrumb "Create #{@user.name()}'s account"
  end
  
  def edit_analyzer_account
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no]
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{params[:su_sys_no]}"
    add_breadcrumb "Reset analyzer access code"
    
    flash.now[:warning] = 'Warning: Resetting an auditor access code will require every analyzer in the State of North Carolina to perform a Data File refresh in order to receive the updated access code.  A reset should only be done as a last resort.'
  end
  
  def save_analyzer_account
    @user = SecurityUser.find_by_su_sys_no params[:user][:su_sys_no]
    add_breadcrumb "Home", "/"
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{@user.su_sys_no}"
    add_breadcrumb "Reset analyzer access code"
    
    access_code = params[:user][:access_code];
    
    if access_code.blank?
      @user.errors.add_to_base "Please enter an access code"
      render :action=>:edit_analyzer_account
    elsif ! /^[0-9]{5}?/.match(access_code)
      @user.errors.add_to_base "Please enter a five digit access code"
      render :action=>:edit_analyzer_account
    else
      @user.inspector.insp_acc_cd = access_code
      @user.inspector.save
      redirect_to :action=>:show, :su_sys_no=>params[:user][:su_sys_no]
    end
  end
  
  def edit_auditor_info
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no]
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{@user.su_sys_no}"
    add_breadcrumb "Edit audit information"
  end
  
  def save_auditor_info
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no]
    
    @user.audit_assignments = params[:assignments]
    @user.district = params[:user][:district]
    @user.validate_password = false
    
    if @user.save
      redirect_to :action=>:show, :su_sys_no=>params[:su_sys_no]
    else
       add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{@user.su_sys_no}"
       add_breadcrumb "Edit audit information"
       render :action=>:edit_auditor_info
    end
  end
  
  def create
    @user = SecurityUser.new
    
    add_breadcrumb "Create User Account"
    
    render :action=>:new
  end
  
  def create_account
    add_breadcrumb "Create User Account"

    params[:user][:password].gsub!(/\s+/, '')
    
    @user = SecurityUser.new(params[:user])
    @user.password_confirmation = @user.password
    @user.current_password = @user.password
    @user.user_role_sys_no = params[:new_user_role_sys_no]
    
    #Check that a role is selected...
    if params[:new_user_role_sys_no].blank?
        @user.errors.add_to_base("The User Role must be selected")
          render :action => :new and return
    end
    
    #Code to process File No. (Access Id)
    if params[:access_id_reqd] == 'yes'
      if !(params[:user][:access_id].to_s.match(/\d+?(\.\d+)?\Z/) == nil ? false : true )
        @user.errors.add(:access_id, "File No. must be entered, and numeric only")
        render :action => :new and return
      else
        if params[:user][:access_id].to_i < 1
          @user.errors.add(:access_id, "File No. cannot be zero")
          render :action => :new and return
        end
      end
      
      dup_fileno  = Inspector.find_by_insp_id(params[:user][:access_id])
      dup_badge = Inspector.find_by_insp_badge_no(params[:user][:access_id])
          
      if dup_fileno            
          @user.errors.add(:access_id, "File No. already exists for another employee. Please enter a different File No.")
          render :action => :new and return
      end
      
      if dup_badge            
          @user.errors.add(:access_id, "File No. is already on file for another employee's badge number. Please enter a different File No.")
          render :action => :new and return
      end
      
    end
    
    if @user.valid?
      @user.su_status_code = 'A'
      @user.su_status_change_by = (SecurityUser.find_by_su_user_id session[:cas_user].upcase).su_sys_no
      @user.su_status_change_reason = 'Account created.'
      
      @user.su_user_id = @user.su_user_id.upcase
      
      if @user.inspector and @user.inspector.insp_auditor_fl == 'Y'
        auditor_role = SecurityRole.find_by_sr_name('Auditor')
        @user.security_roles.push(auditor_role)
      end
      
      if( @user.inspector and @user.inspector.insp_status_fl == 'Y' )
        @user.inspector.insp_type = 'I'
        inspector_role = SecurityRole.find_by_sr_name('Inspector')
        @user.security_roles.push(inspector_role)
      end
      
      if @user.inspector 
        @user.inspector.insp_first_nm = @user.su_first_name.upcase
        @user.inspector.insp_mid_nm   = @user.su_middle_initial.upcase
        @user.inspector.insp_last_nm  = @user.su_last_name.upcase
      end
      
      roles =  []
      
      if params[:roles]
        roles = SecurityRole.get_effective_roles(params[:roles])
        roles = SecurityRole.find(roles)
      end
      
      @user.security_roles = roles
      
      @user.create_inspector if @user.inspector?
      @user.create_auditor if @user.auditor?     
      
      @user.revoke_inspector if !@user.inspector?
      @user.revoke_auditor if !@user.auditor?
      @user.validate_password = false
      
      @user.audit_assignments = params[:assignments]
      
      if !@user.validate_pwd(@user.password)
        render :action=>:new and return
      end
      
      if @user.save
        flash[:notice] = "#{@user.name()}'s account has been created."
        redirect_to :action=>:show, :su_sys_no=>@user.su_sys_no
      else
        render :action=>:new
      end
    else
      render :action=>:new
    end
  end
  
  def grant_ets_access
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no]
    
    @user.grant_ets_access
    
    redirect_to :action=>:show, :su_sys_no=>params[:su_sys_no]
  end
  
  def revoke_ets_access
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no]
    
    @user.revoke_ets_access
    
    redirect_to :action=>:show, :su_sys_no=>params[:su_sys_no]
  end
  
  def edit_details
    @user = SecurityUser.find_by_su_sys_no(params[:su_sys_no])
   
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{params[:su_sys_no]}"
    add_breadcrumb "Edit Details"
  end
  
  def save_details
    @user = SecurityUser.find_by_su_sys_no(params[:user][:su_sys_no])
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{params[:user][:su_sys_no]}"
    add_breadcrumb "Edit Details"
    
    #@user.update_attributes params[:user]
    params[:user][:su_first_name].strip!
    params[:user][:su_middle_initial].strip!
    params[:user][:su_last_name].strip!
    params[:user][:su_user_id].strip!
    
    @user.validate_password = false
    
    # --- Start check for duplicate Inspector Id (File No. or Access ID - All synonomous terms)
    new_access_id = params[:user][:access_id]
    orig_access_id = params[:orig_access_id]
    new_user_role_sys_no = params[:new_user_role_sys_no]
    orig_user_role_sys_no = params[:orig_user_role_sys_no]
    
    #Code to process File No. (Access Id)
    if params[:access_id_reqd] == 'yes'
      if !(params[:user][:access_id].to_s.match(/\d+?(\.\d+)?\Z/) == nil ? false : true )
        @user.errors.add(:access_id, "File No. must be numeric only")
        render :action => :edit_details and return
      else
        if params[:user][:access_id].to_i < 1
          @user.errors.add(:access_id, "File No. cannot be zero")
          render :action => :edit_details and return
        end
      end
    end
    
    if (!orig_access_id.blank?) && (new_access_id != orig_access_id)
      orig_insp = Inspector.find_by_insp_id(orig_access_id)
      new_insp = Inspector.find_by_insp_id(new_access_id)
      
      if new_insp
        if new_insp.insp_sys_no != orig_insp.insp_sys_no
          # If we found an inspector row using the new_access_id, then it must be an existing
          # inspector row.  If the SYS_NOs do not match then an inspector already exists with
          # the new_access_id, so display an action message.
          @user.errors.add( :access_id,  "The File No. - " + new_access_id.to_s + ", already exists for another employee.  Please enter another.")
          render :action => :edit_details and return
        end
      end
    end
    # --- End check for duplicate Inspector Id (File No. or Access ID - All synonomous terms)
    
    @user.attributes = params[:user]
    
    if params[:orig_status] != params[:user][:su_status_code]
      @user.su_status_change_by = (SecurityUser.find_by_su_user_id session[:cas_user].upcase).su_sys_no
      #@user.su_status_change_reason = params[:change_reason]
      
      if @user.active? and @user.auditor?
        @user.grant_ets_access
      end
    end
    
    #save or revoke the user roles
    if !@user.active?
      @user.revoke_ets_access
      @user.revoke_audit_assignments
      #@user.revoke_roles
    else
      roles =  []
      
      if params[:roles]
        roles = SecurityRole.get_effective_roles(params[:roles])
        roles = SecurityRole.find(roles)
      end
      
      @user.security_roles = roles
      @user.set_user_role_sys_no
      
      #Did the role change?  If so, need to write history record...
      if new_user_role_sys_no != orig_user_role_sys_no
        suh = SecurityUsersHistory.new
        suh.suh_su_sys_no                   = @user.su_sys_no
        suh.suh_status_code                 = @user.su_status_code
        suh.suh_status_change_by        = (SecurityUser.find_by_su_user_id session[:cas_user].upcase).su_sys_no
        suh.suh_sr_sys_no                   = new_user_role_sys_no
        suh.suh_status_change_reason  = 'Role changed'
        suh.save
      end
      
      @user.create_inspector if @user.inspector?
      @user.create_auditor if @user.auditor?     
      @user.revoke_inspector if !@user.inspector?
      @user.revoke_auditor if !@user.auditor?
      @user.validate_password = false
      @user.audit_assignments = params[:assignments]
    end
    
    @user.validate_at_least_one_audit_assignment = false
    #if params[:orig_status] !=params[:user][:su_status_code] and params[:change_reason].blank? 
    #  @user.errors.add(:su_status_change_reason, "Please enter the status change reason")
    #  render :action=>:edit_details
    #  return
    #end
    
    if @user.save
      redirect_to :action=>:show, :su_sys_no=>params[:user][:su_sys_no]
    else
      render :action=>:edit_details
    end
  end
  
  def reset_password
    @user = SecurityUser.find_by_su_sys_no params[:su_sys_no]
   
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{params[:su_sys_no]}"
    add_breadcrumb "Reset password"
  end
  
  def reset_password_save
    @user = SecurityUser.find_by_su_sys_no params[:user][:su_sys_no]
    add_breadcrumb "#{@user.name()}'s account", "/user/show?su_sys_no=#{params[:su_sys_no]}"
    add_breadcrumb "Reset password"
    
    @user.password              = params[:user][:password]
    @user.password_confirmation = params[:user][:password]
    @user.current_password      = params[:user][:password]
    
    @user.validate_at_least_one_audit_assignment = false;
    
    if !@user.validate_pwd(@user.password)
      render :action=>:reset_password and return
    end
    
    if @user.save
      flash[:notice] = "#{@user.name()}'s password has been reset."
      redirect_to :action=>:show, :su_sys_no=>params[:user][:su_sys_no]
    else
      render :action=>:reset_password
    end
  end
  
  def show
    @user = SecurityUser.find_by_su_sys_no(params[:su_sys_no])
    add_breadcrumb 'Search', '/user'
    add_breadcrumb "#{@user.name()}'s Account", '#'
  end
  
  def suggest_user_id
    
    ids = SecurityUser.new(params[:user]).suggested_user_ids;
    
    render :json => ids;
  end
  
end